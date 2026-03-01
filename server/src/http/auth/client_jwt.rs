use axum::Json;
use axum::extract::FromRequest;
use axum::http::Request;
use serde::Deserialize;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, decrypt_jwe_direct, decrypt_private_key,
    extract_kid, jwk_from_json, verify_jws,
};

use super::check_signing_key_not_expired;
use super::error::AuthError;

/// Authenticated list of (client_id, pairing_id) pairs from the request body.
#[derive(Debug, Clone)]
pub struct ClientJwtAuth {
    pub clients: Vec<ClientInfo>,
}

/// A single verified client identity.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub client_id: String,
    pub pairing_id: String,
}

#[derive(Debug, Deserialize)]
struct ClientJwtBody {
    client_jwts: Vec<String>,
}

impl FromRequest<AppState> for ClientJwtAuth {
    type Rejection = AppError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Json(body) = Json::<ClientJwtBody>::from_request(req, state)
            .await
            .map_err(|e| AppError::validation(format!("invalid request body: {e}")))?;

        if body.client_jwts.is_empty() {
            return Err(AuthError::Unauthorized("no client_jwts provided".into()).into());
        }

        let verified = verify_all_tokens(&body.client_jwts, state).await?;
        let filtered = filter_valid_pairings(verified, state).await?;

        if filtered.is_empty() {
            return Err(AuthError::Unauthorized("all client tokens filtered out".into()).into());
        }

        Ok(Self { clients: filtered })
    }
}

/// Verify and decrypt all tokens. Any crypto failure rejects ALL (all-or-nothing).
pub(crate) async fn verify_all_tokens(
    tokens: &[String],
    state: &AppState,
) -> Result<Vec<(String, String)>, AppError> {
    let mut pairs = Vec::with_capacity(tokens.len());
    for token in tokens {
        let (client_id, pairing_id) = verify_one_token(token, state).await?;
        pairs.push((client_id, pairing_id));
    }
    Ok(pairs)
}

/// Verify the outer JWS, decrypt the inner JWE, return (client_id, pairing_id).
pub(crate) async fn verify_one_token(
    token: &str,
    state: &AppState,
) -> Result<(String, String), AppError> {
    let kid = extract_kid(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let outer: ClientOuterClaims = verify_jws(token, &public_jwk, PayloadType::Client)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let inner = decrypt_inner_jwe(&outer.client_jwe, &signing_key.private_key, state)?;
    Ok((inner.sub, inner.pairing_id))
}

/// Decrypt the inner JWE to extract ClientInnerClaims.
pub(crate) fn decrypt_inner_jwe(
    jwe_token: &str,
    encrypted_private_key: &str,
    state: &AppState,
) -> Result<ClientInnerClaims, AppError> {
    let private_json = decrypt_private_key(encrypted_private_key, &state.signing_key_secret)
        .map_err(|e| AuthError::InvalidToken(format!("key decrypt failed: {e}")))?;
    let private_jwk = jwk_from_json(&private_json)
        .map_err(|e| AuthError::InvalidToken(format!("invalid private JWK: {e}")))?;

    let plaintext = decrypt_jwe_direct(jwe_token, &private_jwk)
        .map_err(|e| AuthError::InvalidToken(format!("JWE decryption failed: {e}")))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| AuthError::InvalidToken(format!("invalid inner claims: {e}")).into())
}

/// Filter out pairs whose pairing_id is not in client_pairings (soft failure).
///
/// Groups by client_id to avoid redundant DB queries when multiple tokens
/// share the same client.
pub(crate) async fn filter_valid_pairings(
    pairs: Vec<(String, String)>,
    state: &AppState,
) -> Result<Vec<ClientInfo>, AppError> {
    use std::collections::HashMap;

    // Group pairing_ids by client_id to deduplicate DB lookups.
    let mut by_client: HashMap<String, Vec<String>> = HashMap::new();
    for (client_id, pairing_id) in &pairs {
        by_client
            .entry(client_id.clone())
            .or_default()
            .push(pairing_id.clone());
    }

    // Fetch pairings once per unique client_id.
    let mut pairing_sets: HashMap<String, Vec<String>> = HashMap::new();
    for client_id in by_client.keys() {
        let db_pairings = state
            .repository
            .get_client_pairings(client_id)
            .await
            .map_err(AppError::from)?;
        pairing_sets.insert(
            client_id.clone(),
            db_pairings.into_iter().map(|p| p.pairing_id).collect(),
        );
    }

    // Filter original pairs preserving order.
    let valid = pairs
        .into_iter()
        .filter(|(cid, pid)| pairing_sets.get(cid).is_some_and(|ids| ids.contains(pid)))
        .map(|(client_id, pairing_id)| ClientInfo {
            client_id,
            pairing_id,
        })
        .collect();

    Ok(valid)
}

#[cfg(test)]
#[path = "client_jwt_tests.rs"]
mod tests;
