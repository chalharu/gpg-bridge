use uuid::Uuid;

use crate::error::AppError;

struct JwkValidationSpec {
    key_label: &'static str,
    key_use: &'static str,
    alg: &'static str,
}

const SIG_KEY_SPEC: JwkValidationSpec = JwkValidationSpec {
    key_label: "sig key",
    key_use: "sig",
    alg: "ES256",
};

const ENC_KEY_SPEC: JwkValidationSpec = JwkValidationSpec {
    key_label: "enc key",
    key_use: "enc",
    alg: "ECDH-ES+A256KW",
};

/// Validate a JWK sig key and return the (potentially assigned) kid.
pub fn validate_sig_key(key: &mut serde_json::Value) -> Result<String, AppError> {
    validate_key(key, &SIG_KEY_SPEC)
}

/// Validate a JWK enc key and return the (potentially assigned) kid.
pub fn validate_enc_key(key: &mut serde_json::Value) -> Result<String, AppError> {
    validate_key(key, &ENC_KEY_SPEC)
}

fn validate_key(key: &mut serde_json::Value, spec: &JwkValidationSpec) -> Result<String, AppError> {
    let obj = key
        .as_object_mut()
        .ok_or_else(|| AppError::validation(format!("{} must be a JSON object", spec.key_label)))?;
    check_required_fields(
        obj,
        &[
            ("kty", "EC"),
            ("use", spec.key_use),
            ("crv", "P-256"),
            ("alg", spec.alg),
        ],
    )?;
    check_base64url_coord(obj, "x")?;
    check_base64url_coord(obj, "y")?;
    Ok(assign_kid_if_missing(obj))
}

fn check_required_fields(
    obj: &serde_json::Map<String, serde_json::Value>,
    fields: &[(&str, &str)],
) -> Result<(), AppError> {
    for (field, expected) in fields {
        check_field_eq(obj, field, expected)?;
    }
    Ok(())
}

fn check_field_eq(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected: &str,
) -> Result<(), AppError> {
    let val = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation(format!("missing or invalid '{field}' in JWK")))?;
    if val != expected {
        return Err(AppError::validation(format!(
            "expected {field}=\"{expected}\", got \"{val}\""
        )));
    }
    Ok(())
}

fn check_base64url_coord(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<(), AppError> {
    let val = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation(format!("missing '{field}' coordinate in JWK")))?;
    if val.len() != 43 {
        return Err(AppError::validation(format!(
            "'{field}' must be 43 chars base64url, got {} chars",
            val.len()
        )));
    }
    Ok(())
}

fn assign_kid_if_missing(obj: &mut serde_json::Map<String, serde_json::Value>) -> String {
    if let Some(kid) = obj.get("kid").and_then(|v| v.as_str()) {
        kid.to_owned()
    } else {
        let kid = Uuid::new_v4().to_string();
        obj.insert("kid".to_owned(), serde_json::Value::String(kid.clone()));
        kid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_sig_key() -> serde_json::Value {
        json!({
            "kty": "EC",
            "use": "sig",
            "crv": "P-256",
            "alg": "ES256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        })
    }

    fn valid_enc_key() -> serde_json::Value {
        json!({
            "kty": "EC",
            "use": "enc",
            "crv": "P-256",
            "alg": "ECDH-ES+A256KW",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        })
    }

    #[test]
    fn valid_sig_key_passes_and_assigns_kid() {
        let mut key = valid_sig_key();
        let kid = validate_sig_key(&mut key).unwrap();
        assert!(!kid.is_empty());
        assert_eq!(key["kid"].as_str().unwrap(), kid);
    }

    #[test]
    fn sig_key_preserves_existing_kid() {
        let mut key = valid_sig_key();
        key["kid"] = json!("my-kid");
        let kid = validate_sig_key(&mut key).unwrap();
        assert_eq!(kid, "my-kid");
    }

    #[test]
    fn sig_key_wrong_alg_fails() {
        let mut key = valid_sig_key();
        key["alg"] = json!("RS256");
        assert!(validate_sig_key(&mut key).is_err());
    }

    #[test]
    fn enc_key_valid_passes() {
        let mut key = valid_enc_key();
        let kid = validate_enc_key(&mut key).unwrap();
        assert!(!kid.is_empty());
    }

    #[test]
    fn enc_key_wrong_use_fails() {
        let mut key = valid_enc_key();
        key["use"] = json!("sig");
        assert!(validate_enc_key(&mut key).is_err());
    }

    #[test]
    fn missing_x_coord_fails() {
        let mut key = valid_sig_key();
        key.as_object_mut().unwrap().remove("x");
        assert!(validate_sig_key(&mut key).is_err());
    }

    #[test]
    fn short_y_coord_fails() {
        let mut key = valid_sig_key();
        key["y"] = json!("short");
        assert!(validate_sig_key(&mut key).is_err());
    }
}
