use axum::{extract::Path, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::add::{is_valid_keygrip, load_client_gpg_keys, save_gpg_keys};

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

    let (client, mut keys) = load_client_gpg_keys(&state, &auth.client_id).await?;

    let idx = keys
        .iter()
        .position(|k| k.keygrip == keygrip)
        .ok_or_else(|| {
            AppError::not_found(format!("gpg key with keygrip \"{keygrip}\" not found"))
        })?;

    keys.remove(idx);

    save_gpg_keys(&state, &auth.client_id, &keys, &client.updated_at).await
}
