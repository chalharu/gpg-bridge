mod client_jwt;
mod daemon_auth;
mod device_assertion;
mod error;
mod sign_jwt;

pub(crate) use client_jwt::verify_one_token;
pub use client_jwt::{ClientInfo, ClientJwtAuth};
pub(crate) use client_jwt::{filter_valid_pairings, verify_all_tokens};
pub use daemon_auth::DaemonAuthJws;
pub use device_assertion::DeviceAssertionAuth;
pub use error::AuthError;
pub use sign_jwt::SignJwtAuth;

use axum::http::{self, request::Parts};
use josekit::jwk::Jwk;

use crate::jwt::jwk_from_json;
use crate::repository::SigningKeyRow;

/// Extract a bearer token from the `Authorization` header.
pub(crate) fn extract_bearer_token(parts: &Parts) -> Result<String, AuthError> {
    let header = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?;
    let value = header.to_str().map_err(|_| AuthError::MissingToken)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AuthError::MissingToken)?;
    Ok(token.to_owned())
}

/// Build the expected `aud` value: `{base_url}{request_path}`.
pub(crate) fn build_expected_aud(base_url: &str, parts: &Parts) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), parts.uri.path())
}

/// Find a JWK by `kid` inside a JSON array of JWKs.
pub(crate) fn find_public_key_by_kid(public_keys_json: &str, kid: &str) -> Result<Jwk, AuthError> {
    let keys: Vec<serde_json::Value> = serde_json::from_str(public_keys_json)
        .map_err(|e| AuthError::InvalidToken(format!("invalid public_keys JSON: {e}")))?;

    for key_val in &keys {
        if key_val.get("kid").and_then(|v| v.as_str()) == Some(kid) {
            let key_json = serde_json::to_string(key_val)
                .map_err(|e| AuthError::InvalidToken(format!("invalid JWK: {e}")))?;
            return jwk_from_json(&key_json)
                .map_err(|e| AuthError::InvalidToken(format!("invalid JWK: {e}")));
        }
    }

    Err(AuthError::Unauthorized(
        "no matching public key found".into(),
    ))
}

/// Convert a Unix timestamp to an RFC 3339 string.
///
/// Returns an error if the timestamp is out of range (e.g. negative overflow).
pub(crate) fn timestamp_to_rfc3339(ts: i64) -> Result<String, AuthError> {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .ok_or_else(|| AuthError::InvalidToken("invalid timestamp".into()))
}

/// Verify that a signing key has not expired.
pub(crate) fn check_signing_key_not_expired(key: &SigningKeyRow) -> Result<(), AuthError> {
    let now = chrono::Utc::now().to_rfc3339();
    if key.expires_at <= now {
        return Err(AuthError::InvalidToken("signing key has expired".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::generate_signing_key_pair;

    #[test]
    fn extract_bearer_token_parses_valid_header() {
        let parts = http::request::Builder::new()
            .header(http::header::AUTHORIZATION, "Bearer my-token")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        let token = extract_bearer_token(&parts).unwrap();
        assert_eq!(token, "my-token");
    }

    #[test]
    fn extract_bearer_token_rejects_missing_header() {
        let parts = http::request::Builder::new()
            .body(())
            .unwrap()
            .into_parts()
            .0;

        assert!(matches!(
            extract_bearer_token(&parts),
            Err(AuthError::MissingToken)
        ));
    }

    #[test]
    fn extract_bearer_token_rejects_wrong_scheme() {
        let parts = http::request::Builder::new()
            .header(http::header::AUTHORIZATION, "Basic abc123")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        assert!(matches!(
            extract_bearer_token(&parts),
            Err(AuthError::MissingToken)
        ));
    }

    #[test]
    fn build_expected_aud_concatenates_correctly() {
        let parts = http::request::Builder::new()
            .uri("/v1/sign")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        let aud = build_expected_aud("https://api.gpg-bridge.dev", &parts);
        assert_eq!(aud, "https://api.gpg-bridge.dev/v1/sign");
    }

    #[test]
    fn build_expected_aud_trims_trailing_slash() {
        let parts = http::request::Builder::new()
            .uri("/health")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        let aud = build_expected_aud("https://api.gpg-bridge.dev/", &parts);
        assert_eq!(aud, "https://api.gpg-bridge.dev/health");
    }

    #[test]
    fn find_public_key_by_kid_returns_matching_key() {
        let (_priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let pub_json = crate::jwt::jwk_to_json(&pub_jwk).unwrap();
        let keys_json = format!("[{pub_json}]");

        let found = find_public_key_by_kid(&keys_json, &kid).unwrap();
        assert_eq!(found.key_id(), Some(kid.as_str()));
    }

    #[test]
    fn find_public_key_by_kid_returns_error_for_unknown() {
        let (_priv_jwk, pub_jwk, _kid) = generate_signing_key_pair().unwrap();
        let pub_json = crate::jwt::jwk_to_json(&pub_jwk).unwrap();
        let keys_json = format!("[{pub_json}]");

        assert!(matches!(
            find_public_key_by_kid(&keys_json, "wrong-kid"),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn timestamp_to_rfc3339_converts_correctly() {
        let result = timestamp_to_rfc3339(1_700_000_000).unwrap();
        assert!(result.contains("2023"));
    }

    #[test]
    fn timestamp_to_rfc3339_rejects_invalid() {
        // i64::MIN is out of range for chrono
        assert!(timestamp_to_rfc3339(i64::MIN).is_err());
    }
}
