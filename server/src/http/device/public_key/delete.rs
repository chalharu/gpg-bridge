use axum::{extract::Path, extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

// ---------------------------------------------------------------------------
// DELETE /device/public_key/{kid}
// ---------------------------------------------------------------------------

pub async fn delete_public_key(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Path(kid): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let client = state
        .repository
        .get_client_by_id(&auth.client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;

    let mut keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys)
        .map_err(|e| AppError::internal(format!("invalid public_keys JSON: {e}")))?;

    let idx = find_key_index(&keys, &kid)?;
    check_last_key_constraints(&keys, &kid)?;
    check_in_flight(&state, &kid).await?;

    keys.remove(idx);
    let default_kid = reassign_default_kid(&keys, &client.default_kid, &kid)?;
    let keys_json = serde_json::to_string(&keys)
        .map_err(|e| AppError::internal(format!("failed to serialize keys: {e}")))?;
    let now = chrono::Utc::now().to_rfc3339();

    let updated = state
        .repository
        .update_client_public_keys(
            &auth.client_id,
            &keys_json,
            &default_kid,
            &now,
            &client.updated_at,
        )
        .await
        .map_err(AppError::from)?;

    if !updated {
        return Err(AppError::conflict("concurrent modification, please retry"));
    }

    Ok(StatusCode::NO_CONTENT)
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
