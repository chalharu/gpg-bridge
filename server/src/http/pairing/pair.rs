use axum::extract::FromRequest;
use axum::{Json, extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::{DeviceAssertionAuth, check_signing_key_not_expired};
use crate::jwt::{PairingClaims, PayloadType, extract_kid, jwk_from_json, verify_jws};
use crate::repository::{PairingRow, SigningKeyRow};

use super::helpers::build_client_jwt_token;
use super::notifier::PairedEventData;

// ---------------------------------------------------------------------------
// POST /pairing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub pairing_jwt: String,
}

#[derive(Debug, Serialize)]
pub struct PairingResponse {
    pub ok: bool,
    pub client_id: String,
    pub pairing_id: String,
}

pub async fn pair_device(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    req: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse, AppError> {
    let Json(body) = Json::<PairRequest>::from_request(req, &state)
        .await
        .map_err(|e| AppError::validation(format!("invalid request body: {e}")))?;

    let (pairing_id, signing_key) = verify_pairing_token(&body.pairing_jwt, &state).await?;
    fetch_and_validate_pairing(&state, &pairing_id).await?;
    consume_and_link_pairing(&state, &pairing_id, &auth.client_id).await?;

    // Build the client_jwt and deliver via SSE paired event.
    let client_jwt = build_client_jwt_token(&state, &signing_key, &auth.client_id, &pairing_id)?;
    state.pairing_notifier.notify(
        &pairing_id,
        PairedEventData {
            client_jwt,
            client_id: auth.client_id.clone(),
        },
    );

    Ok(Json(PairingResponse {
        ok: true,
        client_id: auth.client_id,
        pairing_id,
    }))
}

/// Extract kid, look up signing key, verify JWS, return (pairing_id, signing_key).
async fn verify_pairing_token(
    token: &str,
    state: &AppState,
) -> Result<(String, SigningKeyRow), AppError> {
    let kid = extract_kid(token)
        .map_err(|e| AppError::validation(format!("invalid pairing_jwt: {e}")))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing"))?
        .ok_or_else(|| {
            AppError::validation("unknown signing key in pairing_jwt").with_instance("/pairing")
        })?;

    // Issue 6: check signing key expiry
    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key).map_err(|e| {
        tracing::error!("invalid public JWK: {e}");
        AppError::internal("internal server error")
    })?;

    let claims: PairingClaims = verify_jws(token, &public_jwk, PayloadType::Pairing)
        .map_err(|e| AppError::gone(format!("pairing_jwt invalid or expired: {e}")))?;

    Ok((claims.sub, signing_key))
}

/// Fetch the pairing record and validate it is not expired or consumed.
async fn fetch_and_validate_pairing(
    state: &AppState,
    pairing_id: &str,
) -> Result<PairingRow, AppError> {
    let pairing = state
        .repository
        .get_pairing_by_id(pairing_id)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing"))?
        .ok_or_else(|| AppError::gone("pairing not found or expired").with_instance("/pairing"))?;

    // Issue 5: use proper DateTime comparison instead of string ordering
    let expired = DateTime::parse_from_rfc3339(&pairing.expired)
        .map_err(|e| {
            tracing::error!("failed to parse pairing expired timestamp: {e}");
            AppError::internal("internal server error")
        })?
        .with_timezone(&Utc);

    if expired <= Utc::now() {
        return Err(AppError::gone("pairing expired").with_instance("/pairing"));
    }
    if pairing.client_id.is_some() {
        return Err(AppError::conflict("pairing already consumed").with_instance("/pairing"));
    }
    Ok(pairing)
}

/// Consume the pairing and create the client_pairing link.
async fn consume_and_link_pairing(
    state: &AppState,
    pairing_id: &str,
    client_id: &str,
) -> Result<(), AppError> {
    let consumed = state
        .repository
        .consume_pairing(pairing_id, client_id)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing"))?;

    if !consumed {
        return Err(AppError::conflict("pairing already consumed").with_instance("/pairing"));
    }

    let now_str = chrono::Utc::now().to_rfc3339();
    state
        .repository
        .create_client_pairing(client_id, pairing_id, &now_str)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing"))
}
