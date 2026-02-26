use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::{GpgKeyEntry, GpgKeyListResponse};

// ---------------------------------------------------------------------------
// GET /device/gpg_key
// ---------------------------------------------------------------------------

pub async fn list_gpg_keys(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    let client = state
        .repository
        .get_client_by_id(&auth.client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let gpg_keys: Vec<GpgKeyEntry> = serde_json::from_str(&client.gpg_keys)
        .map_err(|e| AppError::internal(format!("invalid gpg_keys JSON: {e}")))?;

    Ok(Json(GpgKeyListResponse { gpg_keys }))
}
