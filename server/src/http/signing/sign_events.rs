use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::WatchStream;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::authenticate_daemon_request;
use crate::http::rate_limit::{acquire_sse_slot, resolve_client_ip};
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
    let client_ip = resolve_client_ip(&request, INSTANCE)?;
    let (mut parts, _body) = request.into_parts();
    let auth = authenticate_daemon_request(&mut parts, &state, INSTANCE).await?;
    let request_id = auth.request_id;

    let guard = acquire_sse_slot(
        &state,
        client_ip,
        &request_id,
        "SSE connection already active for this request",
        INSTANCE,
    )?;

    let rx = state.sign_event_notifier.subscribe(&request_id);

    let full_request = state
        .repository
        .get_full_request_by_id(&request_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| AppError::not_found("request not found").with_instance(INSTANCE))?;

    let expiry = parse_expiry(&full_request.expired).map_err(|e| e.with_instance(INSTANCE))?;

    if let Some(data) = completed_event_data(&full_request.status, full_request.signature.clone()) {
        state.sign_event_notifier.unsubscribe(&request_id);
        return Ok(build_immediate_response(data, guard));
    }

    Ok(build_waiting_response(state, request_id, guard, rx, expiry))
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

        let remaining = self.remaining_duration();
        if remaining.is_zero() {
            return Some(Ok(self.expire_request().await));
        }

        tokio::select! {
            biased;
            item = self.watch.next() => Some(Ok(self.handle_watch_item(item).await)),
            () = tokio::time::sleep(remaining) => Some(Ok(self.expire_request().await)),
        }
    }

    fn remaining_duration(&self) -> Duration {
        (self.expiry - Utc::now()).to_std().unwrap_or_default()
    }

    async fn expire_request(&mut self) -> Event {
        self.done = true;
        self.write_expired_audit_log().await;
        signature_event(&SignEventData {
            signature: None,
            status: "expired".to_owned(),
        })
    }

    async fn handle_watch_item(&mut self, item: Option<Option<SignEventData>>) -> Event {
        match item {
            Some(Some(data)) => {
                self.done = true;
                signature_event(&data)
            }
            Some(None) => Event::default().comment(""),
            None => {
                self.done = true;
                self.check_db_fallback()
                    .await
                    .map(|data| signature_event(&data))
                    .unwrap_or_else(|| Event::default().comment("closed"))
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

        completed_event_data(&request.status, request.signature)
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

fn completed_event_data(status: &str, signature: Option<String>) -> Option<SignEventData> {
    match status {
        "approved" => Some(SignEventData {
            signature,
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
