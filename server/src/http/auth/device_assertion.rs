use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::jwt::{DeviceAssertionClaims, decode_jws_unverified, extract_kid, verify_jws_with_key};

use super::error::AuthError;
use super::{
    build_expected_aud, extract_bearer_token, find_public_key_by_kid, timestamp_to_rfc3339,
};
use crate::http::AppState;

/// Authenticated device identity extracted from `Authorization: Bearer`.
#[derive(Debug, Clone)]
pub struct DeviceAssertionAuth {
    pub client_id: String,
}

impl FromRequestParts<AppState> for DeviceAssertionAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let unverified: DeviceAssertionClaims =
            decode_jws_unverified(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let kid = extract_kid(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let client = state
            .repository
            .get_client_by_id(&unverified.sub)
            .await
            .map_err(AppError::from)?
            .ok_or(AuthError::Unauthorized("client not found".into()))?;

        let public_jwk = find_public_key_by_kid(&client.public_keys, &kid)?;
        let claims: DeviceAssertionClaims = verify_jws_with_key(&token, &public_jwk)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Validate iss==sub on verified claims (defense-in-depth)
        validate_iss_eq_sub(&claims)?;
        validate_aud(&claims, &build_expected_aud(&state.base_url, parts))?;
        validate_exp_window(&claims)?;
        store_jti(state, &claims.jti, claims.exp).await?;

        Ok(Self {
            client_id: claims.sub,
        })
    }
}

fn validate_iss_eq_sub(claims: &DeviceAssertionClaims) -> Result<(), AuthError> {
    if claims.iss != claims.sub {
        return Err(AuthError::InvalidToken("iss must equal sub".into()));
    }
    Ok(())
}

fn validate_aud(claims: &DeviceAssertionClaims, expected: &str) -> Result<(), AuthError> {
    if claims.aud != expected {
        return Err(AuthError::InvalidToken("aud mismatch".into()));
    }
    Ok(())
}

/// Enforce a maximum token lifetime of 60 seconds (`exp - iat <= 60`).
fn validate_exp_window(claims: &DeviceAssertionClaims) -> Result<(), AuthError> {
    const MAX_WINDOW_SECS: i64 = 60;
    let window = claims.exp.saturating_sub(claims.iat);
    if window > MAX_WINDOW_SECS || window <= 0 {
        return Err(AuthError::InvalidToken(
            "token lifetime out of range".into(),
        ));
    }
    Ok(())
}

async fn store_jti(state: &AppState, jti: &str, exp: i64) -> Result<(), AppError> {
    let expired = timestamp_to_rfc3339(exp)?;
    let stored = state
        .repository
        .store_jti(jti, &expired)
        .await
        .map_err(AppError::from)?;
    if !stored {
        return Err(AuthError::InvalidToken("jti replay detected".into()).into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "device_assertion_tests.rs"]
mod tests;
