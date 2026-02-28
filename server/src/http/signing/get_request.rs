use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;
use crate::jwt::{PayloadType, SignClaims, decrypt_private_key, jwk_from_json, sign_jws};

use super::types::{GetSignRequestItem, GetSignRequestResponse};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn get_sign_request(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    let fid = &auth.client_id;

    // Get client pairings for this FID
    let pairings = state
        .repository
        .get_client_pairings(fid)
        .await
        .map_err(AppError::from)?;

    if pairings.is_empty() {
        return Ok(Json(GetSignRequestResponse { requests: vec![] }));
    }

    // Get all pending requests where this client_id is eligible
    let pending = state
        .repository
        .get_pending_requests_for_client(fid)
        .await
        .map_err(AppError::from)?;

    if pending.is_empty() {
        return Ok(Json(GetSignRequestResponse { requests: vec![] }));
    }

    // Prepare signing key for issuing sign_jwts
    let signing_key = state
        .repository
        .get_active_signing_key()
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::internal("no active signing key"))?;

    let private_json = decrypt_private_key(&signing_key.private_key, &state.signing_key_secret)
        .map_err(|e| AppError::internal(format!("key decrypt failed: {e}")))?;
    let private_jwk = jwk_from_json(&private_json)
        .map_err(|e| AppError::internal(format!("invalid JWK: {e}")))?;

    let mut result_items = Vec::new();

    for request in &pending {
        // Extract pairing_id for this client from pairing_ids JSON
        let pairing_ids: serde_json::Value = serde_json::from_str(&request.pairing_ids)
            .map_err(|e| AppError::internal(format!("invalid pairing_ids: {e}")))?;
        let pairing_id = match pairing_ids.get(fid).and_then(|v| v.as_str()) {
            Some(pid) => pid.to_owned(),
            None => continue,
        };

        // Extract encrypted_data for this client
        let encrypted_payload =
            extract_encrypted_data(&request.encrypted_payloads, fid).unwrap_or_default();

        // Parse daemon_enc_public_key as JSON value
        let daemon_enc_public_key: serde_json::Value =
            serde_json::from_str(&request.daemon_enc_public_key)
                .map_err(|e| AppError::internal(format!("invalid daemon_enc_public_key: {e}")))?;

        // Issue sign_jwt
        let exp = chrono::Utc::now().timestamp() + state.request_jwt_validity_seconds as i64;
        let claims = SignClaims {
            sub: request.request_id.clone(),
            client_id: fid.clone(),
            payload_type: PayloadType::Sign,
            exp,
        };
        let sign_jwt = sign_jws(&claims, &private_jwk, &signing_key.kid)
            .map_err(|e| AppError::internal(format!("sign_jwt signing failed: {e}")))?;

        result_items.push(GetSignRequestItem {
            request_id: request.request_id.clone(),
            sign_jwt,
            encrypted_payload,
            pairing_id,
            daemon_enc_public_key,
        });
    }

    tracing::info!(
        client_id = %fid,
        count = result_items.len(),
        "sign requests fetched"
    );

    Ok(Json(GetSignRequestResponse {
        requests: result_items,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_encrypted_data(encrypted_payloads: &Option<String>, client_id: &str) -> Option<String> {
    let payloads_str = encrypted_payloads.as_ref()?;
    let payloads: Vec<serde_json::Value> = serde_json::from_str(payloads_str).ok()?;
    for p in payloads {
        if p.get("client_id").and_then(|v| v.as_str()) == Some(client_id) {
            return p
                .get("encrypted_data")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());
        }
    }
    None
}
