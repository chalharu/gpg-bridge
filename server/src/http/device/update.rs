use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::DeviceUpdateRequest;
use super::register::check_device_token_available;

pub async fn update_device(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Json(body): Json<DeviceUpdateRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.device_token.is_none() && body.default_kid.is_none() {
        return Err(AppError::validation(
            "at least one of device_token or default_kid is required",
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();

    if let Some(ref token) = body.device_token {
        check_device_token_available(&state, token, &auth.client_id).await?;
        state
            .repository
            .update_client_device_token(&auth.client_id, token, &now)
            .await
            .map_err(AppError::from)?;
    }

    if let Some(ref kid) = body.default_kid {
        validate_default_kid_exists(&state, &auth.client_id, kid).await?;
        state
            .repository
            .update_client_default_kid(&auth.client_id, kid, &now)
            .await
            .map_err(AppError::from)?;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn validate_default_kid_exists(
    state: &AppState,
    client_id: &str,
    kid: &str,
) -> Result<(), AppError> {
    let client = state
        .repository
        .get_client_by_id(client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys)
        .map_err(|e| AppError::internal(format!("invalid public_keys JSON: {e}")))?;

    let has_enc_key = keys.iter().any(|k| {
        k.get("use").and_then(|v| v.as_str()) == Some("enc")
            && k.get("kid").and_then(|v| v.as_str()) == Some(kid)
    });

    if !has_enc_key {
        return Err(AppError::validation(
            "default_kid must match a registered enc key",
        ));
    }
    Ok(())
}
