use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;
use crate::jwt::{DeviceClaims, PayloadType, extract_kid, jwk_from_json, verify_jws_ignore_exp};

use super::register::issue_device_jwt;
use super::{DeviceRefreshRequest, DeviceResponse};

pub async fn refresh_device_jwt(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Json(body): Json<DeviceRefreshRequest>,
) -> Result<impl IntoResponse, AppError> {
    let claims = verify_submitted_jwt(&state, &body.device_jwt).await?;

    if claims.sub != auth.client_id {
        return Err(AppError::unauthorized(
            "device_jwt sub does not match authenticated client",
        ));
    }

    check_device_jwt_validity(&state, &auth.client_id).await?;

    let now = chrono::Utc::now();
    state
        .repository
        .update_device_jwt_issued_at(&auth.client_id, &now.to_rfc3339(), &now.to_rfc3339())
        .await
        .map_err(AppError::from)?;

    let device_jwt = issue_device_jwt(&state, &auth.client_id, now).await?;

    Ok(Json(DeviceResponse { device_jwt }))
}

async fn verify_submitted_jwt(state: &AppState, token: &str) -> Result<DeviceClaims, AppError> {
    let kid =
        extract_kid(token).map_err(|e| AppError::validation(format!("invalid device_jwt: {e}")))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::unauthorized("unknown signing key"))?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| AppError::internal(format!("invalid signing key: {e}")))?;

    verify_jws_ignore_exp(token, &public_jwk, PayloadType::Device)
        .map_err(|e| AppError::unauthorized(format!("device_jwt verification failed: {e}")))
}

async fn check_device_jwt_validity(state: &AppState, client_id: &str) -> Result<(), AppError> {
    let client = state
        .repository
        .get_client_by_id(client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let issued_at = chrono::DateTime::parse_from_rfc3339(&client.device_jwt_issued_at)
        .map_err(|e| AppError::internal(format!("invalid device_jwt_issued_at: {e}")))?;

    let expiry = issued_at + chrono::Duration::seconds(state.device_jwt_validity_seconds as i64);
    let now = chrono::Utc::now();

    if expiry <= now {
        return Err(AppError::unauthorized(
            "device_jwt expired, re-register via POST /device",
        ));
    }
    Ok(())
}
