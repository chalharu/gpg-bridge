//! Cryptographic operations for daemon E2E signing flow.
//!
//! Provides ES256 key generation, JWS signing, and ECDH-ES+A256KW JWE encryption.

use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use josekit::{
    jwe::{self, JweHeader, alg::ecdh_es::EcdhEsJweAlgorithm},
    jwk::{
        Jwk, KeyPair,
        alg::ec::{EcCurve, EcKeyPair},
    },
    jws::{ES256, JwsHeader},
    jwt::{self, JwtPayload},
};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// Generate an ES256 (P-256) ephemeral key pair for daemon authentication.
///
/// Returns `(private_jwk, public_key_json, kid)`. The `public_key_json` conforms
/// to the `DaemonPublicKey` schema (`kty`, `crv`, `x`, `y`, `alg` only).
pub(crate) fn generate_es256_keypair() -> anyhow::Result<(Jwk, Value, String)> {
    let kid = Uuid::new_v4().to_string();
    let pair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| anyhow!("ES256 key generation failed: {e}"))?;
    let mut private_jwk = pair.to_jwk_key_pair();
    private_jwk.set_key_id(&kid);
    let public_json = build_public_key_json(&pair, "ES256")?;
    Ok((private_jwk, public_json, kid))
}

/// Generate a P-256 ephemeral key pair for ECDH-ES+A256KW E2E encryption.
///
/// Returns `(private_jwk, public_key_json)`. The `public_key_json` conforms
/// to the `DaemonEncPublicKey` schema (`kty`, `crv`, `x`, `y`, `alg` only).
pub(crate) fn generate_ecdh_keypair() -> anyhow::Result<(Jwk, Value)> {
    let pair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| anyhow!("ECDH key generation failed: {e}"))?;
    let private_jwk = pair.to_jwk_key_pair();
    let public_json = build_public_key_json(&pair, "ECDH-ES+A256KW")?;
    Ok((private_jwk, public_json))
}

/// Build a minimal public key JSON matching the `DaemonPublicKey`/`DaemonEncPublicKey` schemas.
///
/// Only includes `kty`, `crv`, `x`, `y`, `alg` — no additional properties,
/// as required by the OpenAPI `additionalProperties: false` constraint.
fn build_public_key_json(pair: &EcKeyPair, alg: &str) -> anyhow::Result<Value> {
    let pub_jwk = pair.to_jwk_public_key();
    let map = pub_jwk.as_ref();
    let kty = map.get("kty").ok_or_else(|| anyhow!("missing kty"))?;
    let crv = map.get("crv").ok_or_else(|| anyhow!("missing crv"))?;
    let x = map.get("x").ok_or_else(|| anyhow!("missing x"))?;
    let y = map.get("y").ok_or_else(|| anyhow!("missing y"))?;
    Ok(serde_json::json!({
        "kty": kty,
        "crv": crv,
        "x": x,
        "y": y,
        "alg": alg,
    }))
}

/// Sign a `daemon_auth_jws` token (ES256) for authenticating Phase 2 / SSE / Cancel.
///
/// The JWS payload contains `request_jwt`, `aud`, `iat`, `exp`, and `jti`.
pub(crate) fn sign_daemon_auth_jws(
    private_jwk: &Jwk,
    kid: &str,
    request_jwt: &str,
    aud: &str,
    exp: i64,
) -> anyhow::Result<String> {
    let claims = DaemonAuthClaims {
        request_jwt: request_jwt.to_owned(),
        aud: aud.to_owned(),
        iat: chrono::Utc::now().timestamp(),
        exp,
        jti: Uuid::new_v4().to_string(),
    };
    let payload = claims_to_payload(&claims)?;
    let mut header = JwsHeader::new();
    header.set_key_id(kid);
    header.set_token_type("JWT");
    let signer = ES256
        .signer_from_jwk(private_jwk)
        .map_err(|e| anyhow!("failed to create ES256 signer: {e}"))?;
    jwt::encode_with_signer(&payload, &header, &*signer)
        .map_err(|e| anyhow!("daemon_auth_jws signing failed: {e}"))
}

/// Encrypt plaintext using ECDH-ES+A256KW + A256GCM (JWE compact serialization).
pub(crate) fn encrypt_jwe_a256kw(
    recipient_public_key: &Value,
    plaintext: &[u8],
) -> anyhow::Result<String> {
    let public_jwk = value_to_jwk(recipient_public_key)?;
    let mut header = JweHeader::new();
    header.set_content_encryption("A256GCM");
    let encrypter = EcdhEsJweAlgorithm::EcdhEsA256kw
        .encrypter_from_jwk(&public_jwk)
        .map_err(|e| anyhow!("failed to create ECDH-ES+A256KW encrypter: {e}"))?;
    jwe::serialize_compact(plaintext, &header, &*encrypter)
        .map_err(|e| anyhow!("JWE encryption failed: {e}"))
}

/// Extract the `exp` claim from a JWT without verifying the signature.
pub(crate) fn extract_jwt_exp(token: &str) -> anyhow::Result<i64> {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    anyhow::ensure!(parts.len() >= 2, "invalid JWT format");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow!("failed to decode JWT payload: {e}"))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("failed to parse JWT payload: {e}"))?;
    payload["exp"]
        .as_i64()
        .ok_or_else(|| anyhow!("JWT payload missing exp claim"))
}

#[derive(Serialize)]
struct DaemonAuthClaims {
    request_jwt: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
}

fn claims_to_payload<T: Serialize>(claims: &T) -> anyhow::Result<JwtPayload> {
    let value = serde_json::to_value(claims)?;
    let map = value
        .as_object()
        .ok_or_else(|| anyhow!("claims must serialize to a JSON object"))?;
    JwtPayload::from_map(map.clone()).map_err(|e| anyhow!("failed to create JWT payload: {e}"))
}

fn value_to_jwk(value: &Value) -> anyhow::Result<Jwk> {
    let json =
        serde_json::to_vec(value).map_err(|e| anyhow!("failed to serialize JWK value: {e}"))?;
    Jwk::from_bytes(&json).map_err(|e| anyhow!("failed to parse JWK: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_es256_keypair_produces_valid_key() {
        let (_private, public, kid) = generate_es256_keypair().unwrap();
        assert_eq!(public["kty"], "EC");
        assert_eq!(public["crv"], "P-256");
        assert_eq!(public["alg"], "ES256");
        assert!(public["x"].is_string());
        assert!(public["y"].is_string());
        assert!(!kid.is_empty());
        // Only the expected fields should be present (additionalProperties: false)
        let obj = public.as_object().unwrap();
        assert_eq!(obj.len(), 5, "DaemonPublicKey must have exactly 5 fields");
    }

    #[test]
    fn generate_es256_keypair_private_key_has_d() {
        let (private, _, _) = generate_es256_keypair().unwrap();
        assert!(private.as_ref().get("d").is_some());
    }

    #[test]
    fn generate_ecdh_keypair_produces_correct_alg() {
        let (_private, public) = generate_ecdh_keypair().unwrap();
        assert_eq!(public["kty"], "EC");
        assert_eq!(public["crv"], "P-256");
        assert_eq!(public["alg"], "ECDH-ES+A256KW");
        let obj = public.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "DaemonEncPublicKey must have exactly 5 fields"
        );
    }

    #[test]
    fn sign_daemon_auth_jws_produces_valid_jwt() {
        let (private, _public, kid) = generate_es256_keypair().unwrap();
        let token = sign_daemon_auth_jws(
            &private,
            &kid,
            "test-request-jwt",
            "https://api.example.com/sign-request",
            1_900_000_000,
        )
        .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
    }

    #[test]
    fn sign_daemon_auth_jws_contains_correct_claims() {
        let (private, _public, kid) = generate_es256_keypair().unwrap();
        let token = sign_daemon_auth_jws(
            &private,
            &kid,
            "my-req-jwt",
            "https://api.example.com/sign-request",
            1_900_000_000,
        )
        .unwrap();
        // Decode payload (without verification) to check claims
        let parts: Vec<&str> = token.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["request_jwt"], "my-req-jwt");
        assert_eq!(payload["aud"], "https://api.example.com/sign-request");
        assert_eq!(payload["exp"], 1_900_000_000);
        assert!(payload["iat"].is_number());
        assert!(payload["jti"].is_string());
    }

    #[test]
    fn encrypt_jwe_a256kw_produces_5_part_compact() {
        let (_private, public) = generate_ecdh_keypair().unwrap();
        let jwe = encrypt_jwe_a256kw(&public, b"test plaintext").unwrap();
        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5, "JWE compact must have 5 parts");
    }

    #[test]
    fn jwe_roundtrip_encrypt_then_decrypt() {
        let (private, public) = generate_ecdh_keypair().unwrap();
        let plaintext = b"hello world e2e";
        let jwe_token = encrypt_jwe_a256kw(&public, plaintext).unwrap();
        let decrypter = EcdhEsJweAlgorithm::EcdhEsA256kw
            .decrypter_from_jwk(&private)
            .unwrap();
        let (recovered, _) = jwe::deserialize_compact(&jwe_token, &*decrypter).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn jwe_header_contains_expected_algorithm() {
        let (_private, public) = generate_ecdh_keypair().unwrap();
        let jwe_token = encrypt_jwe_a256kw(&public, b"data").unwrap();
        let header_b64 = jwe_token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ECDH-ES+A256KW");
        assert_eq!(header["enc"], "A256GCM");
        assert!(header.get("epk").is_some(), "JWE header must contain epk");
    }

    #[test]
    fn extract_jwt_exp_parses_correctly() {
        let (private, _, kid) = generate_es256_keypair().unwrap();
        let token =
            sign_daemon_auth_jws(&private, &kid, "req", "https://example.com", 1_234_567_890)
                .unwrap();
        let exp = extract_jwt_exp(&token).unwrap();
        assert_eq!(exp, 1_234_567_890);
    }

    #[test]
    fn extract_jwt_exp_errors_on_invalid_format() {
        assert!(extract_jwt_exp("invalid").is_err());
    }

    #[test]
    fn extract_jwt_exp_errors_on_missing_exp() {
        // Build a JWT-like token with no exp
        let payload = serde_json::json!({"request_jwt": "test"});
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let fake_token = format!("header.{b64}.signature");
        assert!(extract_jwt_exp(&fake_token).is_err());
    }

    #[test]
    fn value_to_jwk_roundtrip() {
        let (_private, public) = generate_ecdh_keypair().unwrap();
        let jwk = value_to_jwk(&public).unwrap();
        assert_eq!(jwk.as_ref().get("kty").unwrap(), "EC");
    }

    #[test]
    fn encrypt_jwe_with_invalid_key_fails() {
        let invalid_key = serde_json::json!({"kty": "oct"});
        let result = encrypt_jwe_a256kw(&invalid_key, b"data");
        assert!(result.is_err());
    }
}
