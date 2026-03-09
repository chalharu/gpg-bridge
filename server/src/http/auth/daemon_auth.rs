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

pub(crate) async fn authenticate_daemon_request(
    parts: &mut Parts,
    state: &AppState,
    instance: &str,
) -> Result<DaemonAuthJws, AppError> {
    let token = extract_bearer_token(parts).map_err(|error| auth_error(error, instance))?;

    let outer: DaemonAuthClaims = decode_jws_unverified(&token)
        .map_err(|e| auth_error(AuthError::InvalidToken(e.to_string()), instance))?;

    let request_claims = verify_request_jwt(&outer.request_jwt, state, instance).await?;
    let request_id = request_claims.sub;

    let daemon_pub_jwk = fetch_daemon_key(state, &request_id, instance).await?;

    let verified: DaemonAuthClaims = verify_jws_with_key(&token, &daemon_pub_jwk)
        .map_err(|e| auth_error(AuthError::InvalidToken(e.to_string()), instance))?;

    let expected_aud = build_expected_aud(&state.base_url, parts);
    validate_aud(&verified, &expected_aud).map_err(|error| auth_error(error, instance))?;

    store_jti_with_expiration(state, &verified.jti, verified.exp)
        .await
        .map_err(|error| error.with_instance(instance))?;

    Ok(DaemonAuthJws { request_id })
}

impl FromRequestParts<AppState> for DaemonAuthJws {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let instance = parts.uri.path().to_owned();
        authenticate_daemon_request(parts, state, &instance).await
    }
}

fn auth_error(error: AuthError, instance: &str) -> AppError {
    AppError::unauthorized(error.to_string()).with_instance(instance)
}

/// Verify the inner `request_jwt` using the server's signing key.
async fn verify_request_jwt(
    request_jwt: &str,
    state: &AppState,
    instance: &str,
) -> Result<RequestClaims, AppError> {
    let kid = extract_kid(request_jwt)
        .map_err(|e| auth_error(AuthError::InvalidToken(e.to_string()), instance))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(|error| AppError::from(error).with_instance(instance))?
        .ok_or_else(|| {
            auth_error(
                AuthError::InvalidToken("unknown signing key".into()),
                instance,
            )
        })?;

    check_signing_key_not_expired(&signing_key).map_err(|error| auth_error(error, instance))?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| auth_error(AuthError::InvalidToken(e.to_string()), instance))?;

    verify_jws(request_jwt, &public_jwk, PayloadType::Request)
        .map_err(|e| auth_error(AuthError::InvalidToken(e.to_string()), instance))
}

/// Fetch the daemon public key from the requests table.
async fn fetch_daemon_key(
    state: &AppState,
    request_id: &str,
    instance: &str,
) -> Result<josekit::jwk::Jwk, AppError> {
    let request = state
        .repository
        .get_request_by_id(request_id)
        .await
        .map_err(|error| AppError::from(error).with_instance(instance))?
        .ok_or_else(|| {
            auth_error(
                AuthError::Unauthorized("request not found".into()),
                instance,
            )
        })?;

    jwk_from_json(&request.daemon_public_key).map_err(|e| {
        auth_error(
            AuthError::InvalidToken(format!("invalid daemon_public_key: {e}")),
            instance,
        )
    })
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
