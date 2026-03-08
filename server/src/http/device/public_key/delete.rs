use axum::{extract::Path, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::{load_client_public_keys, save_public_keys};

// ---------------------------------------------------------------------------
// DELETE /device/public_key/{kid}
// ---------------------------------------------------------------------------

pub async fn delete_public_key(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Path(kid): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (client, mut keys) = load_client_public_keys(&state, &auth.client_id).await?;

    let idx = find_key_index(&keys, &kid)?;
    check_last_key_constraints(&keys, &kid)?;
    check_in_flight(&state, &kid).await?;

    keys.remove(idx);
    let default_kid = reassign_default_kid(&keys, &client.default_kid, &kid)?;
    save_public_keys(
        &state,
        &auth.client_id,
        &keys,
        &default_kid,
        &client.updated_at,
    )
    .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_key_index(keys: &[serde_json::Value], kid: &str) -> Result<usize, AppError> {
    keys.iter()
        .position(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
        .ok_or_else(|| AppError::not_found(format!("key with kid \"{kid}\" not found")))
}

fn check_last_key_constraints(keys: &[serde_json::Value], kid: &str) -> Result<(), AppError> {
    let target_use = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
        .and_then(|k| k.get("use").and_then(|v| v.as_str()))
        .unwrap_or("");

    let count = keys
        .iter()
        .filter(|k| k.get("use").and_then(|v| v.as_str()) == Some(target_use))
        .count();

    if count <= 1 {
        return Err(AppError::conflict(format!(
            "cannot delete the last {target_use} key"
        )));
    }
    Ok(())
}

async fn check_in_flight(state: &AppState, kid: &str) -> Result<(), AppError> {
    let in_flight = state
        .repository
        .is_kid_in_flight(kid)
        .await
        .map_err(AppError::from)?;
    if in_flight {
        return Err(AppError::conflict(
            "key is referenced by an in-flight signing request",
        ));
    }
    Ok(())
}

/// Reassign default_kid when the current default is deleted (FINDING-9).
fn reassign_default_kid(
    keys: &[serde_json::Value],
    current: &str,
    deleted_kid: &str,
) -> Result<String, AppError> {
    if current != deleted_kid {
        return Ok(current.to_owned());
    }
    keys.iter()
        .filter(|k| k.get("use").and_then(|v| v.as_str()) == Some("enc"))
        .filter_map(|k| k.get("kid").and_then(|v| v.as_str()))
        .next()
        .map(|s| s.to_owned())
        .ok_or_else(|| AppError::internal("no enc key available for default_kid reassignment"))
}
