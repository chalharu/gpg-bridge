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
mod tests {
    use super::*;
    use crate::jwt::claims::DeviceClaims;
    use crate::jwt::key_management::generate_signing_key_pair;

    fn test_key_pair() -> (Jwk, Jwk, String) {
        generate_signing_key_pair().unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-1".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000,
        };

        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();
        let verified: DeviceClaims = verify_jws(&token, &pub_jwk, PayloadType::Device).unwrap();

        assert_eq!(verified.sub, "fid-1");
        assert_eq!(verified.payload_type, PayloadType::Device);
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (priv_jwk, _pub_jwk, kid) = test_key_pair();
        let (_other_priv, other_pub, _) = test_key_pair();

        let claims = DeviceClaims {
            sub: "fid-2".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000,
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let result: anyhow::Result<DeviceClaims> =
            verify_jws(&token, &other_pub, PayloadType::Device);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_payload_type_fails() {
        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-3".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000,
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let result: anyhow::Result<DeviceClaims> =
            verify_jws(&token, &pub_jwk, PayloadType::Client);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn extract_kid_returns_correct_value() {
        let (priv_jwk, _pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-4".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000,
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let extracted = extract_kid(&token).unwrap();
        assert_eq!(extracted, kid);
    }

    #[test]
    fn extract_kid_rejects_garbage() {
        assert!(extract_kid("not-a-jwt").is_err());
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-expired".into(),
            payload_type: PayloadType::Device,
            exp: 1_000_000_000, // 2001 – well in the past
        };

        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();
        let result: anyhow::Result<DeviceClaims> =
            verify_jws(&token, &pub_jwk, PayloadType::Device);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn verify_accepts_valid_future_token() {
        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-valid".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000, // 2030
        };

        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();
        let verified: DeviceClaims = verify_jws(&token, &pub_jwk, PayloadType::Device).unwrap();
        assert_eq!(verified.sub, "fid-valid");
    }

    #[test]
    fn decode_jws_unverified_returns_payload() {
        let (priv_jwk, _pub_jwk, kid) = test_key_pair();
        let claims = DeviceClaims {
            sub: "fid-unverified".into(),
            payload_type: PayloadType::Device,
            exp: 1_900_000_000,
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let decoded: DeviceClaims = decode_jws_unverified(&token).unwrap();
        assert_eq!(decoded.sub, "fid-unverified");
    }

    #[test]
    fn decode_jws_unverified_rejects_garbage() {
        assert!(decode_jws_unverified::<DeviceClaims>("not-a-jwt").is_err());
    }

    #[test]
    fn verify_jws_with_key_roundtrip() {
        use crate::jwt::claims::DeviceAssertionClaims;

        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceAssertionClaims {
            iss: "fid-1".into(),
            sub: "fid-1".into(),
            aud: "https://api.example.com/sign".into(),
            exp: 1_900_000_000,
            iat: 1_900_000_000 - 30,
            jti: "jti-uuid".into(),
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let verified: DeviceAssertionClaims = verify_jws_with_key(&token, &pub_jwk).unwrap();
        assert_eq!(verified.sub, "fid-1");
        assert_eq!(verified.aud, "https://api.example.com/sign");
    }

    #[test]
    fn verify_jws_with_key_wrong_key_fails() {
        use crate::jwt::claims::DeviceAssertionClaims;

        let (priv_jwk, _pub_jwk, kid) = test_key_pair();
        let (_other_priv, other_pub, _) = test_key_pair();
        let claims = DeviceAssertionClaims {
            iss: "fid-1".into(),
            sub: "fid-1".into(),
            aud: "https://api.example.com/sign".into(),
            exp: 1_900_000_000,
            iat: 1_900_000_000 - 30,
            jti: "jti-uuid".into(),
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let result: anyhow::Result<DeviceAssertionClaims> = verify_jws_with_key(&token, &other_pub);
        assert!(result.is_err());
    }

    #[test]
    fn verify_jws_with_key_rejects_expired() {
        use crate::jwt::claims::DeviceAssertionClaims;

        let (priv_jwk, pub_jwk, kid) = test_key_pair();
        let claims = DeviceAssertionClaims {
            iss: "fid-1".into(),
            sub: "fid-1".into(),
            aud: "https://api.example.com/sign".into(),
            exp: 1_000_000_000, // past
            iat: 1_000_000_000 - 30,
            jti: "jti-uuid".into(),
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let result: anyhow::Result<DeviceAssertionClaims> = verify_jws_with_key(&token, &pub_jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }
}
