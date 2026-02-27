use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;
use crate::repository::ClientRow;

use super::{GpgKeyEntry, GpgKeyRegisterRequest};

// ---------------------------------------------------------------------------
// POST /device/gpg_key
// ---------------------------------------------------------------------------

pub async fn add_gpg_key(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Json(body): Json<GpgKeyRegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.gpg_keys.is_empty() {
        return Err(AppError::validation("gpg_keys must not be empty"));
    }

    validate_gpg_keys(&body.gpg_keys)?;

    let (client, existing) = load_client_gpg_keys(&state, &auth.client_id).await?;
    let merged = merge_gpg_keys(existing, body.gpg_keys);

    save_gpg_keys(&state, &auth.client_id, &merged, &client.updated_at).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate each GPG key entry.
fn validate_gpg_keys(keys: &[GpgKeyEntry]) -> Result<(), AppError> {
    for key in keys {
        if !is_valid_keygrip(&key.keygrip) {
            return Err(AppError::validation(format!(
                "invalid keygrip: \"{}\"",
                key.keygrip
            )));
        }
        if !is_valid_key_id(&key.key_id) {
            return Err(AppError::validation(format!(
                "invalid key_id: \"{}\"",
                key.key_id
            )));
        }
        if !key.public_key.is_object() || key.public_key.as_object().is_none_or(|m| m.is_empty()) {
            return Err(AppError::validation(
                "public_key must be a non-empty JSON object",
            ));
        }
    }
    Ok(())
}

/// 40-character hex string.
pub(super) fn is_valid_keygrip(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Hex string with optional `0x` prefix; maxLength 42 per OpenAPI spec.
fn is_valid_key_id(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    !hex.is_empty() && s.len() <= 42 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Merge new keys into existing, dedup by keygrip preferring new entries.
fn merge_gpg_keys(existing: Vec<GpgKeyEntry>, new_keys: Vec<GpgKeyEntry>) -> Vec<GpgKeyEntry> {
    let mut merged = existing;
    for new_key in new_keys {
        if let Some(pos) = merged.iter().position(|k| k.keygrip == new_key.keygrip) {
            merged[pos] = new_key;
        } else {
            merged.push(new_key);
        }
    }
    merged
}

/// Load a client row and parse its `gpg_keys` JSON into a `Vec<GpgKeyEntry>`.
pub(super) async fn load_client_gpg_keys(
    state: &AppState,
    client_id: &str,
) -> Result<(ClientRow, Vec<GpgKeyEntry>), AppError> {
    let client = state
        .repository
        .get_client_by_id(client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let keys: Vec<GpgKeyEntry> = serde_json::from_str(&client.gpg_keys)
        .map_err(|e| AppError::internal(format!("invalid gpg_keys JSON: {e}")))?;

    Ok((client, keys))
}

/// Serialize keys and persist via optimistic locking.
pub(super) async fn save_gpg_keys(
    state: &AppState,
    client_id: &str,
    keys: &[GpgKeyEntry],
    expected_updated_at: &str,
) -> Result<StatusCode, AppError> {
    let keys_json = serde_json::to_string(keys)
        .map_err(|e| AppError::internal(format!("failed to serialize gpg_keys: {e}")))?;
    let now = chrono::Utc::now().to_rfc3339();

    let updated = state
        .repository
        .update_client_gpg_keys(client_id, &keys_json, &now, expected_updated_at)
        .await
        .map_err(AppError::from)?;

    if !updated {
        return Err(AppError::conflict("concurrent modification, please retry"));
    }

    Ok(StatusCode::NO_CONTENT)
}
