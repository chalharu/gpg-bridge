use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, PayloadType, RequestClaims, decode_jws_unverified, extract_kid,
    jwk_from_json, verify_jws, verify_jws_with_key,
};

use super::error::AuthError;
use super::{
    build_expected_aud, check_signing_key_not_expired, extract_bearer_token,
    store_jti_with_expiration,
};

/// Authenticated request identity from daemon `Authorization: Bearer`.
#[derive(Debug, Clone)]
pub struct DaemonAuthJws {
    pub request_id: String,
}

impl FromRequestParts<AppState> for DaemonAuthJws {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;

        // Step 1: Decode outer JWS (unverified) to get request_jwt
        let outer: DaemonAuthClaims =
            decode_jws_unverified(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Steps 2-3: Verify inner request_jwt with server signing key
        let request_claims = verify_request_jwt(&outer.request_jwt, state).await?;
        let request_id = &request_claims.sub;

        // Step 4: Fetch daemon_public_key from DB
        let daemon_pub_jwk = fetch_daemon_key(state, request_id).await?;

        // Step 5: Verify outer JWS with daemon_public_key
        let verified: DaemonAuthClaims = verify_jws_with_key(&token, &daemon_pub_jwk)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Step 6: Check aud
        let expected_aud = build_expected_aud(&state.base_url, parts);
        validate_aud(&verified, &expected_aud)?;

        // Step 7: Check jti replay
        store_jti_with_expiration(state, &verified.jti, verified.exp).await?;

        Ok(Self {
            request_id: request_id.clone(),
        })
    }
}

/// Verify the inner `request_jwt` using the server's signing key.
async fn verify_request_jwt(
    request_jwt: &str,
    state: &AppState,
) -> Result<RequestClaims, AppError> {
    let kid = extract_kid(request_jwt).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    verify_jws(request_jwt, &public_jwk, PayloadType::Request)
        .map_err(|e| AuthError::InvalidToken(e.to_string()).into())
}

/// Fetch the daemon public key from the requests table.
async fn fetch_daemon_key(
    state: &AppState,
    request_id: &str,
) -> Result<josekit::jwk::Jwk, AppError> {
    let request = state
        .repository
        .get_request_by_id(request_id)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::Unauthorized("request not found".into()))?;

    jwk_from_json(&request.daemon_public_key)
        .map_err(|e| AuthError::InvalidToken(format!("invalid daemon_public_key: {e}")).into())
}

fn validate_aud(claims: &DaemonAuthClaims, expected: &str) -> Result<(), AuthError> {
    if claims.aud != expected {
        return Err(AuthError::InvalidToken("aud mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "daemon_auth_tests.rs"]
mod tests;
