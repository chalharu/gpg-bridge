use anyhow::anyhow;
use josekit::{
    jwe::alg::ecdh_es::EcdhEsJweAlgorithm,
    jwe::{self, JweHeader},
    jwk::Jwk,
};

/// Encrypt plaintext bytes using ECDH-ES + A256GCM (Direct Key Agreement).
///
/// Used for `client_jwt` inner encryption where the server both encrypts and
/// decrypts.
pub fn encrypt_jwe_direct(plaintext: &[u8], public_jwk: &Jwk) -> anyhow::Result<String> {
    let mut header = JweHeader::new();
    header.set_content_encryption("A256GCM");

    let encrypter = EcdhEsJweAlgorithm::EcdhEs
        .encrypter_from_jwk(public_jwk)
        .map_err(|e| anyhow!("failed to create ECDH-ES encrypter: {e}"))?;

    jwe::serialize_compact(plaintext, &header, &*encrypter)
        .map_err(|e| anyhow!("JWE encryption (ECDH-ES) failed: {e}"))
}

/// Decrypt a JWE token encrypted with ECDH-ES + A256GCM.
pub fn decrypt_jwe_direct(jwe_token: &str, private_jwk: &Jwk) -> anyhow::Result<Vec<u8>> {
    let decrypter = EcdhEsJweAlgorithm::EcdhEs
        .decrypter_from_jwk(private_jwk)
        .map_err(|e| anyhow!("failed to create ECDH-ES decrypter: {e}"))?;

    let (payload, _header) = jwe::deserialize_compact(jwe_token, &*decrypter)
        .map_err(|e| anyhow!("JWE decryption (ECDH-ES) failed: {e}"))?;
    Ok(payload)
}

/// Encrypt plaintext bytes using ECDH-ES+A256KW + A256GCM (Key Wrapping).
///
/// Used for E2E encryption between Daemon and Phone.
pub fn encrypt_jwe_key_wrap(plaintext: &[u8], public_jwk: &Jwk) -> anyhow::Result<String> {
    let mut header = JweHeader::new();
    header.set_content_encryption("A256GCM");

    let encrypter = EcdhEsJweAlgorithm::EcdhEsA256kw
        .encrypter_from_jwk(public_jwk)
        .map_err(|e| anyhow!("failed to create ECDH-ES+A256KW encrypter: {e}"))?;

    jwe::serialize_compact(plaintext, &header, &*encrypter)
        .map_err(|e| anyhow!("JWE encryption (ECDH-ES+A256KW) failed: {e}"))
}

/// Decrypt a JWE token encrypted with ECDH-ES+A256KW + A256GCM.
pub fn decrypt_jwe_key_wrap(jwe_token: &str, private_jwk: &Jwk) -> anyhow::Result<Vec<u8>> {
    let decrypter = EcdhEsJweAlgorithm::EcdhEsA256kw
        .decrypter_from_jwk(private_jwk)
        .map_err(|e| anyhow!("failed to create ECDH-ES+A256KW decrypter: {e}"))?;

    let (payload, _header) = jwe::deserialize_compact(jwe_token, &*decrypter)
        .map_err(|e| anyhow!("JWE decryption (ECDH-ES+A256KW) failed: {e}"))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::key_management::generate_signing_key_pair;

    fn test_key_pair() -> (Jwk, Jwk) {
        let (priv_jwk, pub_jwk, _kid) = generate_signing_key_pair().unwrap();
        (priv_jwk, pub_jwk)
    }

    #[test]
    fn jwe_direct_roundtrip() {
        let (priv_jwk, pub_jwk) = test_key_pair();
        let plaintext = b"hello direct ECDH-ES";

        let jwe_token = encrypt_jwe_direct(plaintext, &pub_jwk).unwrap();
        let recovered = decrypt_jwe_direct(&jwe_token, &priv_jwk).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn jwe_key_wrap_roundtrip() {
        let (priv_jwk, pub_jwk) = test_key_pair();
        let plaintext = b"hello key-wrap ECDH-ES+A256KW";

        let jwe_token = encrypt_jwe_key_wrap(plaintext, &pub_jwk).unwrap();
        let recovered = decrypt_jwe_key_wrap(&jwe_token, &priv_jwk).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn jwe_direct_wrong_key_fails() {
        let (_priv1, pub1) = test_key_pair();
        let (priv2, _pub2) = test_key_pair();

        let jwe_token = encrypt_jwe_direct(b"secret", &pub1).unwrap();
        let result = decrypt_jwe_direct(&jwe_token, &priv2);
        assert!(result.is_err());
    }

    #[test]
    fn jwe_key_wrap_wrong_key_fails() {
        let (_priv1, pub1) = test_key_pair();
        let (priv2, _pub2) = test_key_pair();

        let jwe_token = encrypt_jwe_key_wrap(b"secret", &pub1).unwrap();
        let result = decrypt_jwe_key_wrap(&jwe_token, &priv2);
        assert!(result.is_err());
    }

    #[test]
    fn jwe_direct_json_payload_roundtrip() {
        let (priv_jwk, pub_jwk) = test_key_pair();
        let payload = serde_json::json!({
            "sub": "fid-123",
            "pairing_id": "pair-uuid"
        });
        let bytes = serde_json::to_vec(&payload).unwrap();

        let jwe_token = encrypt_jwe_direct(&bytes, &pub_jwk).unwrap();
        let recovered = decrypt_jwe_direct(&jwe_token, &priv_jwk).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&recovered).unwrap();

        assert_eq!(value["sub"], "fid-123");
        assert_eq!(value["pairing_id"], "pair-uuid");
    }
}
