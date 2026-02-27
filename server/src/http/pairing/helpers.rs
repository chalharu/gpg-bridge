use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, decrypt_private_key, encrypt_jwe_direct,
    jwk_from_json, sign_jws,
};
use crate::repository::SigningKeyRow;

/// Verify that `pairing_id` belongs to the given `client_id`.
pub(super) async fn verify_pairing_ownership(
    state: &AppState,
    client_id: &str,
    pairing_id: &str,
    instance: &str,
) -> Result<(), AppError> {
    let pairings = state
        .repository
        .get_client_pairings(client_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(instance))?;

    if !pairings.iter().any(|p| p.pairing_id == pairing_id) {
        return Err(AppError::not_found("pairing not found").with_instance(instance));
    }
    Ok(())
}

/// Delete a client_pairing and remove the client entirely when no pairings remain.
/// Uses a single database transaction to avoid race conditions.
pub(super) async fn remove_pairing_and_cleanup(
    state: &AppState,
    client_id: &str,
    pairing_id: &str,
    instance: &str,
) -> Result<(), AppError> {
    let (_pairing_deleted, _client_deleted) = state
        .repository
        .delete_client_pairing_and_cleanup(client_id, pairing_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(instance))?;

    // TODO: If client_deleted, send SSE expired event for any in-flight requests.
    Ok(())
}

/// Build a client_jwt: inner JWE wrapped in an outer JWS.
pub(super) fn build_client_jwt_token(
    state: &AppState,
    signing_key: &SigningKeyRow,
    client_id: &str,
    pairing_id: &str,
) -> Result<String, AppError> {
    let (private_jwk, public_jwk) =
        decode_signing_key_pair(signing_key, &state.signing_key_secret)?;
    let jwe = encrypt_inner_claims(client_id, pairing_id, &public_jwk)?;

    let exp =
        chrono::Utc::now() + chrono::Duration::seconds(state.client_jwt_validity_seconds as i64);
    let outer = ClientOuterClaims {
        payload_type: PayloadType::Client,
        client_jwe: jwe,
        exp: exp.timestamp(),
    };
    sign_jws(&outer, &private_jwk, &signing_key.kid).map_err(|e| {
        tracing::error!("JWS signing failed: {e}");
        AppError::internal("internal server error")
    })
}

fn decode_signing_key_pair(
    signing_key: &SigningKeyRow,
    secret: &str,
) -> Result<(josekit::jwk::Jwk, josekit::jwk::Jwk), AppError> {
    let private_json = decrypt_private_key(&signing_key.private_key, secret).map_err(|e| {
        tracing::error!("key decrypt failed: {e}");
        AppError::internal("internal server error")
    })?;
    let private_jwk = jwk_from_json(&private_json).map_err(|e| {
        tracing::error!("invalid private JWK: {e}");
        AppError::internal("internal server error")
    })?;
    let public_jwk = jwk_from_json(&signing_key.public_key).map_err(|e| {
        tracing::error!("invalid public JWK: {e}");
        AppError::internal("internal server error")
    })?;
    Ok((private_jwk, public_jwk))
}

fn encrypt_inner_claims(
    client_id: &str,
    pairing_id: &str,
    public_jwk: &josekit::jwk::Jwk,
) -> Result<String, AppError> {
    let inner = ClientInnerClaims {
        sub: client_id.to_owned(),
        pairing_id: pairing_id.to_owned(),
    };
    let inner_bytes = serde_json::to_vec(&inner).map_err(|e| {
        tracing::error!("json serialization failed: {e}");
        AppError::internal("internal server error")
    })?;
    encrypt_jwe_direct(&inner_bytes, public_jwk).map_err(|e| {
        tracing::error!("JWE encryption failed: {e}");
        AppError::internal("internal server error")
    })
}
