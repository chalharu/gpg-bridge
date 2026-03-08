use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::super::validation::{validate_enc_key, validate_sig_key};
use super::{AddPublicKeyRequest, load_client_public_keys, save_public_keys};

// ---------------------------------------------------------------------------
// POST /device/public_key
// ---------------------------------------------------------------------------

pub async fn add_public_key(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Json(mut body): Json<AddPublicKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.keys.is_empty() {
        return Err(AppError::validation("keys must not be empty"));
    }

    let (client, existing) = load_client_public_keys(&state, &auth.client_id).await?;

    validate_and_assign_kids(&mut body.keys)?;
    check_duplicate_kids(&body.keys, &existing)?;

    let mut merged = existing;
    merged.extend(body.keys);
    let default_kid = resolve_default_kid(&body.default_kid, &merged, &client.default_kid)?;

    save_public_keys(
        &state,
        &auth.client_id,
        &merged,
        &default_kid,
        &client.updated_at,
    )
    .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate each new key and assign a kid if missing (FINDING-8: renamed).
fn validate_and_assign_kids(keys: &mut [serde_json::Value]) -> Result<(), AppError> {
    for key in keys.iter_mut() {
        let use_field = key
            .get("use")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::validation("each key must have a 'use' field"))?
            .to_owned();
        match use_field.as_str() {
            "sig" => {
                validate_sig_key(key)?;
            }
            "enc" => {
                validate_enc_key(key)?;
            }
            other => {
                return Err(AppError::validation(format!(
                    "unsupported key use: \"{other}\", expected \"sig\" or \"enc\""
                )));
            }
        }
    }
    Ok(())
}

/// Check for duplicate kids within new keys and between new and existing keys.
fn check_duplicate_kids(
    new_keys: &[serde_json::Value],
    existing_keys: &[serde_json::Value],
) -> Result<(), AppError> {
    let new_kids: Vec<&str> = new_keys
        .iter()
        .filter_map(|k| k.get("kid").and_then(|v| v.as_str()))
        .collect();

    // Check for duplicates within the new keys themselves
    for (i, kid) in new_kids.iter().enumerate() {
        if new_kids[i + 1..].contains(kid) {
            return Err(AppError::validation(format!(
                "duplicate kid \"{kid}\" in new keys"
            )));
        }
    }

    // Check for duplicates between new and existing keys
    for kid in &new_kids {
        let exists = existing_keys
            .iter()
            .any(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid));
        if exists {
            return Err(AppError::validation(format!(
                "kid \"{kid}\" already exists"
            )));
        }
    }

    Ok(())
}

fn resolve_default_kid(
    requested: &Option<String>,
    all_keys: &[serde_json::Value],
    current_default: &str,
) -> Result<String, AppError> {
    let kid = match requested {
        Some(kid) => kid.clone(),
        None => return Ok(current_default.to_owned()),
    };
    let is_enc = all_keys.iter().any(|k| {
        k.get("use").and_then(|v| v.as_str()) == Some("enc")
            && k.get("kid").and_then(|v| v.as_str()) == Some(&kid)
    });
    if !is_enc {
        return Err(AppError::validation(
            "default_kid must match a registered enc key",
        ));
    }
    Ok(kid)
}
