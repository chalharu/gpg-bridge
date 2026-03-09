use axum::extract::{Request, State};
use axum::response::Response;
use chrono::{DateTime, Utc};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::check_signing_key_not_expired;
use crate::http::rate_limit::{acquire_sse_slot, resolve_client_ip};
use crate::jwt::{PairingClaims, PayloadType, extract_kid, jwk_from_json, verify_jws};
use crate::repository::SigningKeyRow;

use super::session_stream::{build_immediate_response, build_waiting_response};

const INSTANCE: &str = "/pairing-session";

// ---------------------------------------------------------------------------
// GET /pairing-session  (SSE)
// ---------------------------------------------------------------------------

pub async fn get_pairing_session(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let token = extract_bearer(request.headers())?;
    let (pairing_id, signing_key) = verify_pairing_jwt(&token, &state).await?;
    let client_ip = resolve_client_ip(&request, INSTANCE)?;
    let guard = acquire_sse_slot(
        &state,
        client_ip,
        &pairing_id,
        "SSE connection already active for this pairing",
        INSTANCE,
    )?;

    // Subscribe before DB check to prevent TOCTOU race:
    // notify() between check and subscribe would otherwise be lost.
    let rx = state.pairing_notifier.subscribe(&pairing_id);

    let pairing = check_pairing_state(&state, &pairing_id).await?;

    let expiry = parse_expiry(&pairing.expired).map_err(|e| e.with_instance(INSTANCE))?;

    if let Some(client_id) = pairing.client_id {
        state.pairing_notifier.unsubscribe(&pairing_id);
        return build_immediate_response(&state, &signing_key, client_id, &pairing_id, guard);
    }

    Ok(build_waiting_response(
        state,
        pairing_id,
        signing_key,
        guard,
        rx,
        expiry,
    ))
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
        .map(str::to_owned)
        .ok_or_else(|| AppError::unauthorized("missing Bearer scheme").with_instance(INSTANCE))
}

// ---------------------------------------------------------------------------
// JWT verification (includes signing key expiry check)
// ---------------------------------------------------------------------------

async fn verify_pairing_jwt(
    token: &str,
    state: &AppState,
) -> Result<(String, SigningKeyRow), AppError> {
    let kid = extract_kid(token).map_err(|e| {
        AppError::unauthorized(format!("invalid pairing_jwt: {e}")).with_instance(INSTANCE)
    })?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| {
            AppError::unauthorized("unknown signing key in pairing_jwt").with_instance(INSTANCE)
        })?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key).map_err(|e| {
        tracing::error!("invalid public JWK: {e}");
        AppError::internal("internal server error")
    })?;

    let claims: PairingClaims =
        verify_jws(token, &public_jwk, PayloadType::Pairing).map_err(|e| {
            AppError::unauthorized(format!("pairing_jwt invalid or expired: {e}"))
                .with_instance(INSTANCE)
        })?;

    Ok((claims.sub, signing_key))
}

// ---------------------------------------------------------------------------
// Pairing state check
// ---------------------------------------------------------------------------

async fn check_pairing_state(
    state: &AppState,
    pairing_id: &str,
) -> Result<crate::repository::PairingRow, AppError> {
    let pairing = state
        .repository
        .get_pairing_by_id(pairing_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| AppError::gone("pairing not found or expired").with_instance(INSTANCE))?;

    let expired = parse_expiry(&pairing.expired).map_err(|e| e.with_instance(INSTANCE))?;
    if expired <= Utc::now() {
        return Err(AppError::gone("pairing expired").with_instance(INSTANCE));
    }

    Ok(pairing)
}

fn parse_expiry(expired: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(expired)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            tracing::error!("failed to parse pairing expired: {e}");
            AppError::internal("internal server error")
        })
}
