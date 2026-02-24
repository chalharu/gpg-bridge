use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use josekit::jwk::Jwk;
use josekit::jwk::KeyPair;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use ring::{
    aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf::{self, HKDF_SHA256, KeyType},
    rand::{SecureRandom, SystemRandom},
};
use uuid::Uuid;

use crate::repository::SigningKeyRow;

/// Generate a new EC P-256 signing key pair.
///
/// Returns `(private_jwk, public_jwk, kid)`.
pub fn generate_signing_key_pair() -> anyhow::Result<(Jwk, Jwk, String)> {
    let kid = Uuid::new_v4().to_string();

    let key_pair = EcKeyPair::generate(EcCurve::P256)
        .map_err(|e| anyhow!("EC P-256 key generation failed: {e}"))?;

    let mut private_jwk = key_pair.to_jwk_key_pair();
    let mut public_jwk = key_pair.to_jwk_public_key();

    private_jwk.set_key_id(&kid);
    public_jwk.set_key_id(&kid);

    Ok((private_jwk, public_jwk, kid))
}

/// Build a [`SigningKeyRow`] ready for database storage.
pub fn build_signing_key_row(
    private_jwk: &Jwk,
    public_jwk: &Jwk,
    kid: &str,
    secret: &str,
    validity_days: i64,
) -> anyhow::Result<SigningKeyRow> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::days(validity_days);

    let private_json = jwk_to_json(private_jwk)?;
    let encrypted = encrypt_private_key(&private_json, secret)?;
    let public_json = jwk_to_json(public_jwk)?;

    Ok(SigningKeyRow {
        kid: kid.to_owned(),
        private_key: encrypted,
        public_key: public_json,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        is_active: true,
    })
}

// ---------------------------------------------------------------------------
// AES-128-GCM private key encryption
// ---------------------------------------------------------------------------

/// Output length type for HKDF expand – produces a 16-byte AES-128 key.
struct Aes128KeyLen;

impl KeyType for Aes128KeyLen {
    fn len(&self) -> usize {
        16
    }
}

/// Application-specific HKDF salt for AES key derivation.
const HKDF_SALT: &[u8] = b"gpg-bridge-signing-key-v1";

/// Derive a 128-bit AES key from a secret using HKDF-SHA256.
pub(crate) fn derive_aes_key(secret: &str) -> [u8; 16] {
    let salt = hkdf::Salt::new(HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(secret.as_bytes());
    let info = [b"gpg-bridge-signing-key-encryption" as &[u8]];
    let okm = prk.expand(&info, Aes128KeyLen).expect("HKDF expand failed");
    let mut key = [0u8; 16];
    okm.fill(&mut key).expect("HKDF fill failed");
    key
}

/// Encrypt a private-key JWK JSON string with AES-128-GCM.
///
/// Returns `base64(nonce ‖ ciphertext ‖ tag)`.
pub fn encrypt_private_key(jwk_json: &str, secret: &str) -> anyhow::Result<String> {
    let key_bytes = derive_aes_key(secret);
    let unbound = UnboundKey::new(&AES_128_GCM, &key_bytes)
        .map_err(|_| anyhow!("failed to create AES key"))?;
    let key = LessSafeKey::new(unbound);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("failed to generate nonce"))?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = jwk_json.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("AES-GCM seal failed"))?;

    let mut combined = Vec::with_capacity(12 + in_out.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&in_out);
    Ok(STANDARD.encode(&combined))
}

/// Decrypt an AES-128-GCM–encrypted private key back to a JWK JSON string.
pub fn decrypt_private_key(encrypted_b64: &str, secret: &str) -> anyhow::Result<String> {
    let data = STANDARD
        .decode(encrypted_b64)
        .context("base64 decode failed")?;
    anyhow::ensure!(data.len() > 12, "encrypted data too short");

    let key_bytes = derive_aes_key(secret);
    let unbound = UnboundKey::new(&AES_128_GCM, &key_bytes)
        .map_err(|_| anyhow!("failed to create AES key"))?;
    let key = LessSafeKey::new(unbound);

    let nonce_bytes: [u8; 12] = data[..12]
        .try_into()
        .map_err(|_| anyhow!("invalid nonce length"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = data[12..].to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| anyhow!("AES-GCM open failed (wrong key or corrupted)"))?;

    String::from_utf8(plaintext.to_vec()).context("decrypted data is not valid UTF-8")
}

// ---------------------------------------------------------------------------
// JWK JSON helpers
// ---------------------------------------------------------------------------

/// Serialize a [`Jwk`] to a JSON string.
pub fn jwk_to_json(jwk: &Jwk) -> anyhow::Result<String> {
    serde_json::to_string(jwk.as_ref()).context("failed to serialize JWK")
}

/// Deserialize a JSON string into a [`Jwk`].
pub fn jwk_from_json(json: &str) -> anyhow::Result<Jwk> {
    Jwk::from_bytes(json.as_bytes()).map_err(|e| anyhow!("failed to parse JWK: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_pair_produces_valid_keys() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        assert!(!kid.is_empty());
        assert_eq!(priv_jwk.key_id(), Some(kid.as_str()));
        assert_eq!(pub_jwk.key_id(), Some(kid.as_str()));
        assert_eq!(priv_jwk.key_type(), "EC");
        assert_eq!(pub_jwk.key_type(), "EC");
    }

    #[test]
    fn encrypt_decrypt_private_key_roundtrip() {
        let secret = "my-super-secret";
        let jwk_json = r#"{"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"ghi"}"#;

        let encrypted = encrypt_private_key(jwk_json, secret).unwrap();
        let decrypted = decrypt_private_key(&encrypted, secret).unwrap();

        assert_eq!(decrypted, jwk_json);
    }

    #[test]
    fn decrypt_with_wrong_secret_fails() {
        let jwk_json = r#"{"kty":"EC","crv":"P-256"}"#;
        let encrypted = encrypt_private_key(jwk_json, "correct").unwrap();
        assert!(decrypt_private_key(&encrypted, "wrong").is_err());
    }

    #[test]
    fn derive_aes_key_is_deterministic() {
        let k1 = derive_aes_key("same-secret");
        let k2 = derive_aes_key("same-secret");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_aes_key_differs_for_different_secrets() {
        let k1 = derive_aes_key("secret-a");
        let k2 = derive_aes_key("secret-b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn jwk_json_roundtrip() {
        let (priv_jwk, _, _) = generate_signing_key_pair().unwrap();
        let json = jwk_to_json(&priv_jwk).unwrap();
        let recovered = jwk_from_json(&json).unwrap();
        assert_eq!(recovered.key_type(), "EC");
    }

    #[test]
    fn build_signing_key_row_creates_valid_row() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let row = build_signing_key_row(&priv_jwk, &pub_jwk, &kid, "secret", 90).unwrap();

        assert_eq!(row.kid, kid);
        assert!(row.is_active);
        assert!(!row.private_key.is_empty());
        assert!(!row.public_key.is_empty());
        assert!(!row.created_at.is_empty());
        assert!(!row.expires_at.is_empty());

        // Verify the encrypted private key can be decrypted
        let decrypted_json = decrypt_private_key(&row.private_key, "secret").unwrap();
        let recovered_jwk = jwk_from_json(&decrypted_json).unwrap();
        assert_eq!(recovered_jwk.key_type(), "EC");
    }

    #[test]
    fn decrypt_encrypted_data_too_short() {
        let short = STANDARD.encode([0u8; 8]);
        assert!(decrypt_private_key(&short, "secret").is_err());
    }
}
