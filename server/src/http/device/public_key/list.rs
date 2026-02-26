use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::PublicKeyListResponse;

// ---------------------------------------------------------------------------
// GET /device/public_key
// ---------------------------------------------------------------------------

pub async fn list_public_keys(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    let client = state
        .repository
        .get_client_by_id(&auth.client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys)
        .map_err(|e| AppError::internal(format!("invalid public_keys JSON: {e}")))?;

    Ok(Json(PublicKeyListResponse {
        keys,
        default_kid: client.default_kid,
    }))
}
