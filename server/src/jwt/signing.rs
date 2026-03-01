use anyhow::{Context, anyhow};
use josekit::{
    jwk::Jwk,
    jws::{ES256, JwsHeader},
    jwt::{self, JwtPayload},
};
use serde::{Serialize, de::DeserializeOwned};

use super::claims::PayloadType;

/// Sign a claims struct as a JWS (ES256) and return the compact JWT string.
pub fn sign_jws<T: Serialize>(claims: &T, private_jwk: &Jwk, kid: &str) -> anyhow::Result<String> {
    let payload = claims_to_payload(claims)?;

    let mut header = JwsHeader::new();
    header.set_key_id(kid);
    header.set_token_type("JWT");

    let signer = ES256
        .signer_from_jwk(private_jwk)
        .map_err(|e| anyhow!("failed to create ES256 signer: {e}"))?;

    jwt::encode_with_signer(&payload, &header, &*signer)
        .map_err(|e| anyhow!("JWS signing failed: {e}"))
}

/// Verify a JWS token (ES256), check `payload_type`, and deserialize to `T`.
pub fn verify_jws<T: DeserializeOwned>(
    token: &str,
    public_jwk: &Jwk,
    expected_payload_type: PayloadType,
) -> anyhow::Result<T> {
    let verifier = ES256
        .verifier_from_jwk(public_jwk)
        .map_err(|e| anyhow!("failed to create ES256 verifier: {e}"))?;

    let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
        .map_err(|e| anyhow!("JWS verification failed: {e}"))?;

    check_payload_type(&payload, expected_payload_type)?;
    check_exp(&payload)?;
    payload_to_claims(&payload)
}

/// Extract the `kid` from a JWT header without verifying the signature.
pub fn extract_kid(token: &str) -> anyhow::Result<String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    anyhow::ensure!(parts.len() >= 2, "invalid JWT format");

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .context("failed to decode JWT header")?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).context("failed to parse JWT header")?;

    header
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| anyhow!("JWT header has no kid"))
}

/// Decode a JWS payload without verifying the signature.
///
/// **Caution:** This does NOT validate the signature. Use it only to
/// extract claims needed *before* the signing key is known.
pub fn decode_jws_unverified<T: DeserializeOwned>(token: &str) -> anyhow::Result<T> {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    anyhow::ensure!(parts.len() == 3, "invalid JWT format: expected 3 parts");

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("failed to decode JWT payload")?;

    serde_json::from_slice(&payload_bytes).context("failed to parse JWT payload")
}

/// Verify a JWS token (ES256), check `payload_type`, and deserialize to `T`.
///
/// Unlike [`verify_jws`], this does **not** check `exp`. Use for tokens
/// that may already be expired (e.g. during device_jwt refresh).
pub fn verify_jws_ignore_exp<T: DeserializeOwned>(
    token: &str,
    public_jwk: &Jwk,
    expected_payload_type: PayloadType,
) -> anyhow::Result<T> {
    let verifier = ES256
        .verifier_from_jwk(public_jwk)
        .map_err(|e| anyhow!("failed to create ES256 verifier: {e}"))?;

    let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
        .map_err(|e| anyhow!("JWS verification failed: {e}"))?;

    check_payload_type(&payload, expected_payload_type)?;
    payload_to_claims(&payload)
}

/// Verify a JWS token (ES256), check `exp`, and deserialize to `T`.
///
/// Unlike [`verify_jws`], this does **not** check `payload_type`.
/// Use for tokens that do not carry a `payload_type` field.
pub fn verify_jws_with_key<T: DeserializeOwned>(
    token: &str,
    public_jwk: &Jwk,
) -> anyhow::Result<T> {
    let verifier = ES256
        .verifier_from_jwk(public_jwk)
        .map_err(|e| anyhow!("failed to create ES256 verifier: {e}"))?;

    let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
        .map_err(|e| anyhow!("JWS verification failed: {e}"))?;

    check_exp(&payload)?;
    payload_to_claims(&payload)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

use base64::Engine;

fn claims_to_payload<T: Serialize>(claims: &T) -> anyhow::Result<JwtPayload> {
    let value = serde_json::to_value(claims)?;
    let map = value
        .as_object()
        .ok_or_else(|| anyhow!("claims must serialize to a JSON object"))?;

    let mut payload = JwtPayload::new();
    for (key, val) in map {
        payload.set_claim(key, Some(val.clone()))?;
    }
    Ok(payload)
}

fn payload_to_claims<T: DeserializeOwned>(payload: &JwtPayload) -> anyhow::Result<T> {
    let map = payload.claims_set().clone();
    let value = serde_json::Value::Object(map);
    serde_json::from_value(value).context("failed to deserialize JWT payload")
}

fn check_payload_type(payload: &JwtPayload, expected: PayloadType) -> anyhow::Result<()> {
    let actual = payload
        .claim("payload_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing payload_type claim"))?;

    if actual != expected.as_str() {
        return Err(anyhow!(
            "payload_type mismatch: expected '{}', got '{actual}'",
            expected.as_str(),
        ));
    }
    Ok(())
}

fn check_exp(payload: &JwtPayload) -> anyhow::Result<()> {
    let exp = payload
        .claim("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("missing or invalid exp claim"))?;

    let now = chrono::Utc::now().timestamp();
    if exp <= now {
        return Err(anyhow!("token has expired (exp={exp}, now={now})"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
