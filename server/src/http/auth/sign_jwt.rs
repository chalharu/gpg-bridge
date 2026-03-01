use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{PayloadType, SignClaims, extract_kid, jwk_from_json, verify_jws};

use super::error::AuthError;
use super::{check_signing_key_not_expired, extract_bearer_token};

/// Authenticated sign identity extracted from `Authorization: Bearer <sign_jwt>`.
///
/// The sign_jwt is a JWS issued by the server (not a device), so verification
/// uses the server's signing keys.
#[derive(Debug, Clone)]
pub struct SignJwtAuth {
    pub request_id: String,
    pub client_id: String,
}

impl FromRequestParts<AppState> for SignJwtAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let kid = extract_kid(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let signing_key = state
            .repository
            .get_signing_key_by_kid(&kid)
            .await
            .map_err(AppError::from)?
            .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

        check_signing_key_not_expired(&signing_key)?;

        let public_jwk = jwk_from_json(&signing_key.public_key)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let claims: SignClaims = verify_jws(&token, &public_jwk, PayloadType::Sign)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(Self {
            request_id: claims.sub,
            client_id: claims.client_id,
        })
    }
}

#[cfg(test)]
#[path = "sign_jwt_tests.rs"]
mod tests;
