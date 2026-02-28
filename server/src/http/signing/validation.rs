use crate::error::AppError;

use super::types::{BASE64URL_COORD_LEN, DaemonKey};

pub(super) fn validate_daemon_signing_key(key: &DaemonKey) -> Result<(), AppError> {
    validate_ec_p256_key(key, "ES256", "daemon_public_key")
}

pub(super) fn validate_daemon_enc_key(key: &DaemonKey) -> Result<(), AppError> {
    validate_ec_p256_key(key, "ECDH-ES+A256KW", "daemon_enc_public_key")
}

fn validate_ec_p256_key(key: &DaemonKey, expected_alg: &str, field: &str) -> Result<(), AppError> {
    if key.kty != "EC" {
        return Err(AppError::validation(format!("{field}: kty must be EC")));
    }
    if key.crv != "P-256" {
        return Err(AppError::validation(format!("{field}: crv must be P-256")));
    }
    if !is_valid_base64url_coord(&key.x) {
        return Err(AppError::validation(format!(
            "{field}: x must be 43-char base64url"
        )));
    }
    if !is_valid_base64url_coord(&key.y) {
        return Err(AppError::validation(format!(
            "{field}: y must be 43-char base64url"
        )));
    }
    if key.alg != expected_alg {
        return Err(AppError::validation(format!(
            "{field}: alg must be {expected_alg}"
        )));
    }
    Ok(())
}

pub(super) fn is_valid_base64url_coord(s: &str) -> bool {
    s.len() == BASE64URL_COORD_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_COORD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SHORT_COORD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn make_key(kty: &str, crv: &str, x: &str, y: &str, alg: &str) -> DaemonKey {
        DaemonKey {
            kty: kty.to_owned(),
            crv: crv.to_owned(),
            x: x.to_owned(),
            y: y.to_owned(),
            alg: alg.to_owned(),
        }
    }

    fn valid_signing_key() -> DaemonKey {
        make_key("EC", "P-256", VALID_COORD, VALID_COORD, "ES256")
    }

    fn valid_enc_key() -> DaemonKey {
        make_key("EC", "P-256", VALID_COORD, VALID_COORD, "ECDH-ES+A256KW")
    }

    #[test]
    fn base64url_coord_accepts_valid() {
        assert!(is_valid_base64url_coord(VALID_COORD));
        assert!(is_valid_base64url_coord(
            "abcXYZ012_-abcXYZ012_-abcXYZ012_-abcXYZ012_"
        ));
    }

    #[test]
    fn base64url_coord_rejects_wrong_length() {
        assert!(!is_valid_base64url_coord(SHORT_COORD));
        assert!(!is_valid_base64url_coord(""));
    }

    #[test]
    fn base64url_coord_rejects_invalid_chars() {
        let bad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+";
        assert_eq!(bad.len(), 43);
        assert!(!is_valid_base64url_coord(bad));
    }

    #[test]
    fn signing_key_accepts_valid() {
        assert!(validate_daemon_signing_key(&valid_signing_key()).is_ok());
    }

    #[test]
    fn signing_key_rejects_bad_kty() {
        let k = make_key("RSA", "P-256", VALID_COORD, VALID_COORD, "ES256");
        let err = validate_daemon_signing_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("kty must be EC"));
    }

    #[test]
    fn signing_key_rejects_bad_crv() {
        let k = make_key("EC", "P-384", VALID_COORD, VALID_COORD, "ES256");
        let err = validate_daemon_signing_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("crv must be P-256"));
    }

    #[test]
    fn signing_key_rejects_short_x() {
        let k = make_key("EC", "P-256", SHORT_COORD, VALID_COORD, "ES256");
        let err = validate_daemon_signing_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("x must be 43-char base64url"));
    }

    #[test]
    fn signing_key_rejects_short_y() {
        let k = make_key("EC", "P-256", VALID_COORD, SHORT_COORD, "ES256");
        let err = validate_daemon_signing_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("y must be 43-char base64url"));
    }

    #[test]
    fn signing_key_rejects_wrong_alg() {
        let k = make_key("EC", "P-256", VALID_COORD, VALID_COORD, "RS256");
        let err = validate_daemon_signing_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("alg must be ES256"));
    }

    #[test]
    fn enc_key_accepts_valid() {
        assert!(validate_daemon_enc_key(&valid_enc_key()).is_ok());
    }

    #[test]
    fn enc_key_rejects_wrong_alg() {
        let k = make_key("EC", "P-256", VALID_COORD, VALID_COORD, "ES256");
        let err = validate_daemon_enc_key(&k).unwrap_err();
        assert!(format!("{err:?}").contains("alg must be ECDH-ES+A256KW"));
    }
}
