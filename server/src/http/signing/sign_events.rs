use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::WatchStream;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::check_signing_key_not_expired;
use crate::http::rate_limit::ip_extractor::extract_client_ip;
use crate::http::rate_limit::sse_tracker::SseRejection;
use crate::jwt::{
    DaemonAuthClaims, PayloadType, RequestClaims, decode_jws_unverified, extract_kid,
    jwk_from_json, verify_jws, verify_jws_with_key,
};
use crate::repository::AuditLogRow;

use super::notifier::SignEventData;

const INSTANCE: &str = "/sign-events";
const HEARTBEAT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// GET /sign-events  (SSE)
// ---------------------------------------------------------------------------

pub async fn get_sign_events(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let token = extract_bearer(request.headers())?;

    // Step 1: Decode outer JWS (unverified) to get request_jwt
    let outer: DaemonAuthClaims =
        decode_jws_unverified(&token).map_err(|e| auth_error(&format!("invalid token: {e}")))?;

    // Steps 2-3: Verify inner request_jwt with server signing key
    let request_claims = verify_request_jwt(&outer.request_jwt, &state).await?;
    let request_id = &request_claims.sub;

    // Step 4: Fetch daemon_public_key from DB
    let daemon_pub_jwk = fetch_daemon_key(&state, request_id).await?;

    // Step 5: Verify outer JWS with daemon_public_key
    let verified: DaemonAuthClaims = verify_jws_with_key(&token, &daemon_pub_jwk)
        .map_err(|e| auth_error(&format!("invalid token: {e}")))?;

    // Step 6: Check aud
    let expected_aud = build_expected_aud(&state.base_url, request.uri().path());
    validate_aud(&verified, &expected_aud)?;

    // Step 7: Check jti replay
    store_jti(&state, &verified.jti, verified.exp).await?;

    // Step 8: Extract client IP for SSE rate limiting
    let client_ip = resolve_client_ip(&request)?;

    // Step 9: Acquire SSE slot (request_id as key)
    let guard = acquire_sse_slot(&state, client_ip, request_id)?;

    // Step 10: Subscribe to sign_event_notifier (before DB check to avoid TOCTOU)
    let rx = state.sign_event_notifier.subscribe(request_id);

    // Step 11: Check if result already exists in DB
    let full_request = state
        .repository
        .get_full_request_by_id(request_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| AppError::not_found("request not found").with_instance(INSTANCE))?;

    let expiry = parse_expiry(&full_request.expired)?;

    // If request is already completed, send immediate response
    match full_request.status.as_str() {
        "approved" => {
            state.sign_event_notifier.unsubscribe(request_id);
            return Ok(build_immediate_response(
                SignEventData {
                    signature: full_request.signature.clone(),
                    status: "approved".to_owned(),
                },
                guard,
            ));
        }
        "denied" => {
            state.sign_event_notifier.unsubscribe(request_id);
            return Ok(build_immediate_response(
                SignEventData {
                    signature: None,
                    status: "denied".to_owned(),
                },
                guard,
            ));
        }
        "unavailable" => {
            state.sign_event_notifier.unsubscribe(request_id);
            return Ok(build_immediate_response(
                SignEventData {
                    signature: None,
                    status: "unavailable".to_owned(),
                },
                guard,
            ));
        }
        "cancelled" => {
            state.sign_event_notifier.unsubscribe(request_id);
            return Ok(build_immediate_response(
                SignEventData {
                    signature: None,
                    status: "cancelled".to_owned(),
                },
                guard,
            ));
        }
        _ => {} // created/pending → wait for SSE event
    }

    // Step 12: Wait for SSE event with heartbeat + expiry timeout
    Ok(build_waiting_response(
        state,
        request_id.clone(),
        guard,
        rx,
        expiry,
    ))
}

// ---------------------------------------------------------------------------
// Immediate response (already completed)
// ---------------------------------------------------------------------------

fn build_immediate_response(
    data: SignEventData,
    guard: crate::http::rate_limit::SseConnectionGuard,
) -> Response {
    let json = serde_json::to_string(&data).expect("SignEventData serialization");
    let stream = futures_util::stream::unfold(Some((guard, json)), |slot| async move {
        let (g, json) = slot?;
        let event = Event::default().event("signature").data(json);
        Some((Ok::<_, Infallible>(event), Some((g, String::new()))))
    });
    let stream = stream.take(1);

    Sse::new(stream)
        .keep_alive(KeepAlive::new())
        .into_response()
}

// ---------------------------------------------------------------------------
// Waiting SSE stream (not yet completed)
// ---------------------------------------------------------------------------

fn build_waiting_response(
    state: AppState,
    request_id: String,
    guard: crate::http::rate_limit::SseConnectionGuard,
    rx: tokio::sync::watch::Receiver<Option<SignEventData>>,
    expiry: DateTime<Utc>,
) -> Response {
    let stream = async_stream(state, request_id, rx, guard, expiry);

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(HEARTBEAT_SECS))
                .event(Event::default().event("heartbeat")),
        )
        .into_response()
}

fn async_stream(
    state: AppState,
    request_id: String,
    rx: tokio::sync::watch::Receiver<Option<SignEventData>>,
    guard: crate::http::rate_limit::SseConnectionGuard,
    expiry: DateTime<Utc>,
) -> impl tokio_stream::Stream<Item = Result<Event, Infallible>> {
    futures_util::stream::unfold(
        StreamState::new(state, request_id, rx, guard, expiry),
        |mut ctx| async move { ctx.next_event().await.map(|event| (event, ctx)) },
    )
}

struct StreamState {
    state: AppState,
    request_id: String,
    watch: WatchStream<Option<SignEventData>>,
    _guard: crate::http::rate_limit::SseConnectionGuard,
    expiry: DateTime<Utc>,
    done: bool,
}

impl StreamState {
    fn new(
        state: AppState,
        request_id: String,
        rx: tokio::sync::watch::Receiver<Option<SignEventData>>,
        guard: crate::http::rate_limit::SseConnectionGuard,
        expiry: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            request_id,
            watch: WatchStream::new(rx),
            _guard: guard,
            expiry,
            done: false,
        }
    }

    async fn next_event(&mut self) -> Option<Result<Event, Infallible>> {
        if self.done {
            return None;
        }

        let remaining = (self.expiry - Utc::now()).to_std().unwrap_or_default();
        if remaining.is_zero() {
            self.done = true;
            self.write_expired_audit_log().await;
            let data = SignEventData {
                signature: None,
                status: "expired".to_owned(),
            };
            return Some(Ok(signature_event(&data)));
        }

        tokio::select! {
            biased;
            item = self.watch.next() => match item {
                Some(Some(data)) => {
                    self.done = true;
                    Some(Ok(signature_event(&data)))
                }
                Some(None) => {
                    // Initial None from watch channel — keep stream alive.
                    Some(Ok(Event::default().comment("")))
                }
                None => {
                    // Channel closed. Check DB as fallback.
                    self.done = true;
                    let event = self
                        .check_db_fallback()
                        .await
                        .map(|data| signature_event(&data))
                        .unwrap_or_else(|| Event::default().comment("closed"));
                    Some(Ok(event))
                }
            },
            () = tokio::time::sleep(remaining) => {
                // Request expired — send expired event and terminate.
                self.done = true;
                self.write_expired_audit_log().await;
                let data = SignEventData {
                    signature: None,
                    status: "expired".to_owned(),
                };
                Some(Ok(signature_event(&data)))
            }
        }
    }

    async fn check_db_fallback(&self) -> Option<SignEventData> {
        let request = self
            .state
            .repository
            .get_full_request_by_id(&self.request_id)
            .await
            .ok()??;

        match request.status.as_str() {
            "approved" => Some(SignEventData {
                signature: request.signature,
                status: "approved".to_owned(),
            }),
            "denied" => Some(SignEventData {
                signature: None,
                status: "denied".to_owned(),
            }),
            "unavailable" => Some(SignEventData {
                signature: None,
                status: "unavailable".to_owned(),
            }),
            "cancelled" => Some(SignEventData {
                signature: None,
                status: "cancelled".to_owned(),
            }),
            _ => None,
        }
    }

    async fn write_expired_audit_log(&self) {
        let row = AuditLogRow {
            log_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event_type: "sign_expired".to_owned(),
            request_id: self.request_id.clone(),
            request_ip: None,
            target_client_ids: None,
            responding_client_id: None,
            error_code: None,
            error_message: None,
        };
        if let Err(e) = self.state.repository.create_audit_log(&row).await {
            tracing::error!(
                request_id = %self.request_id,
                "audit log write failed for sign_expired: {e:?}"
            );
        }
    }
}

fn signature_event(data: &SignEventData) -> Event {
    let json = serde_json::to_string(data).expect("SignEventData serialization");
    Event::default().event("signature").data(json)
}

/// Cleanup is handled exclusively in `Drop` to avoid double unsubscribe.
impl Drop for StreamState {
    fn drop(&mut self) {
        self.state.sign_event_notifier.unsubscribe(&self.request_id);
    }
}

// ---------------------------------------------------------------------------
// Bearer token extraction
// ---------------------------------------------------------------------------

fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            AppError::unauthorized("missing authorization token").with_instance(INSTANCE)
        })?
        .to_str()
        .map_err(|_| {
            AppError::unauthorized("invalid authorization header").with_instance(INSTANCE)
        })?;

    value
        .strip_prefix("Bearer ")
        .map(|t| t.to_owned())
        .ok_or_else(|| AppError::unauthorized("missing Bearer scheme").with_instance(INSTANCE))
}

// ---------------------------------------------------------------------------
// Auth helpers (mirrors daemon_auth.rs logic for SSE context)
// ---------------------------------------------------------------------------

fn auth_error(msg: &str) -> AppError {
    AppError::unauthorized(msg.to_owned()).with_instance(INSTANCE)
}

/// Build expected `aud` value: `{base_url}{path}`.
fn build_expected_aud(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

async fn verify_request_jwt(
    request_jwt: &str,
    state: &AppState,
) -> Result<RequestClaims, AppError> {
    let kid =
        extract_kid(request_jwt).map_err(|e| auth_error(&format!("invalid request_jwt: {e}")))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| auth_error("unknown signing key in request_jwt"))?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key).map_err(|e| {
        tracing::error!("invalid public JWK: {e}");
        AppError::internal("internal server error")
    })?;

    verify_jws(request_jwt, &public_jwk, PayloadType::Request)
        .map_err(|e| auth_error(&format!("invalid request_jwt: {e}")))
}

async fn fetch_daemon_key(
    state: &AppState,
    request_id: &str,
) -> Result<josekit::jwk::Jwk, AppError> {
    let request = state
        .repository
        .get_request_by_id(request_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| auth_error("request not found"))?;

    jwk_from_json(&request.daemon_public_key)
        .map_err(|e| auth_error(&format!("invalid daemon_public_key: {e}")))
}

fn validate_aud(claims: &DaemonAuthClaims, expected: &str) -> Result<(), AppError> {
    if claims.aud != expected {
        return Err(auth_error("aud mismatch"));
    }
    Ok(())
}

async fn store_jti(state: &AppState, jti: &str, exp: i64) -> Result<(), AppError> {
    let expired = crate::http::auth::timestamp_to_rfc3339(exp)?;
    let stored = state
        .repository
        .store_jti(jti, &expired)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?;
    if !stored {
        return Err(auth_error("jti replay detected"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSE connection limit
// ---------------------------------------------------------------------------

fn acquire_sse_slot(
    state: &AppState,
    ip: std::net::IpAddr,
    request_id: &str,
) -> Result<crate::http::rate_limit::SseConnectionGuard, AppError> {
    state
        .sse_tracker
        .try_acquire(ip, request_id.to_owned())
        .map_err(|rejection| match rejection {
            SseRejection::IpLimitExceeded { .. } => {
                AppError::too_many_requests("SSE connection limit per IP exceeded")
                    .with_instance(INSTANCE)
            }
            SseRejection::KeyLimitExceeded { .. } => {
                AppError::too_many_requests("SSE connection already active for this request")
                    .with_instance(INSTANCE)
            }
        })
}

// ---------------------------------------------------------------------------
// IP extraction
// ---------------------------------------------------------------------------

fn resolve_client_ip(request: &Request) -> Result<std::net::IpAddr, AppError> {
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .cloned();
    extract_client_ip(request.headers(), connect_info.as_ref())
        .ok_or_else(|| AppError::internal("could not determine client IP").with_instance(INSTANCE))
}

// ---------------------------------------------------------------------------
// Expiry parsing
// ---------------------------------------------------------------------------

fn parse_expiry(expired: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(expired)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            tracing::error!("failed to parse request expired: {e}");
            AppError::internal("internal server error")
        })
}
