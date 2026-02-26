use axum::{extract::Path, extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::GpgKeyEntry;
use super::add::is_valid_keygrip;

// ---------------------------------------------------------------------------
// DELETE /device/gpg_key/{keygrip}
// ---------------------------------------------------------------------------

pub async fn delete_gpg_key(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Path(keygrip): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !is_valid_keygrip(&keygrip) {
        return Err(AppError::validation(format!(
            "invalid keygrip format: \"{keygrip}\""
        )));
    }

    let client = state
        .repository
        .get_client_by_id(&auth.client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let mut keys: Vec<GpgKeyEntry> = serde_json::from_str(&client.gpg_keys)
        .map_err(|e| AppError::internal(format!("invalid gpg_keys JSON: {e}")))?;

    let idx = keys
        .iter()
        .position(|k| k.keygrip == keygrip)
        .ok_or_else(|| {
            AppError::not_found(format!("gpg key with keygrip \"{keygrip}\" not found"))
        })?;

    keys.remove(idx);

    let keys_json = serde_json::to_string(&keys)
        .map_err(|e| AppError::internal(format!("failed to serialize gpg_keys: {e}")))?;
    let now = chrono::Utc::now().to_rfc3339();

    let updated = state
        .repository
        .update_client_gpg_keys(&auth.client_id, &keys_json, &now, &client.updated_at)
        .await
        .map_err(AppError::from)?;

    if !updated {
        return Err(AppError::conflict("concurrent modification, please retry"));
    }

    Ok(StatusCode::NO_CONTENT)
}
