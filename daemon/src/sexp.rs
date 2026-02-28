use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Convert a JWK public key to a canonical S-expression (binary).
///
/// Supports EC keys (P-256, P-384, P-521) and RSA keys.
pub(crate) fn jwk_to_sexp(jwk: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    let kty = jwk["kty"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing kty field in JWK"))?;
    match kty {
        "EC" => ec_to_sexp(jwk),
        "RSA" => rsa_to_sexp(jwk),
        _ => Err(anyhow::anyhow!("unsupported key type: {kty}")),
    }
}

fn ec_to_sexp(jwk: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    let crv = jwk["crv"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing crv field in JWK"))?;
    let curve_name = match crv {
        "P-256" => "NIST P-256",
        "P-384" => "NIST P-384",
        "P-521" => "NIST P-521",
        _ => return Err(anyhow::anyhow!("unsupported EC curve: {crv}")),
    };

    let x = decode_b64url(jwk, "x")?;
    let y = decode_b64url(jwk, "y")?;

    // Uncompressed point: 0x04 || x || y
    let mut q = Vec::with_capacity(1 + x.len() + y.len());
    q.push(0x04);
    q.extend_from_slice(&x);
    q.extend_from_slice(&y);

    // (public-key(ecc(curve <name>)(q <data>)))
    let mut buf = Vec::new();
    open(&mut buf);
    atom(&mut buf, b"public-key");
    open(&mut buf);
    atom(&mut buf, b"ecc");
    open(&mut buf);
    atom(&mut buf, b"curve");
    atom(&mut buf, curve_name.as_bytes());
    close(&mut buf);
    open(&mut buf);
    atom(&mut buf, b"q");
    atom(&mut buf, &q);
    close(&mut buf);
    close(&mut buf);
    close(&mut buf);
    Ok(buf)
}

fn rsa_to_sexp(jwk: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    let n = decode_b64url(jwk, "n")?;
    let e = decode_b64url(jwk, "e")?;

    // (public-key(rsa(n <data>)(e <data>)))
    let mut buf = Vec::new();
    open(&mut buf);
    atom(&mut buf, b"public-key");
    open(&mut buf);
    atom(&mut buf, b"rsa");
    open(&mut buf);
    atom(&mut buf, b"n");
    atom(&mut buf, &n);
    close(&mut buf);
    open(&mut buf);
    atom(&mut buf, b"e");
    atom(&mut buf, &e);
    close(&mut buf);
    close(&mut buf);
    close(&mut buf);
    Ok(buf)
}

fn decode_b64url(jwk: &serde_json::Value, field: &str) -> anyhow::Result<Vec<u8>> {
    let value = jwk[field]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing {field} field in JWK"))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| anyhow::anyhow!("invalid base64url in JWK field {field}: {e}"))
}

/// Write canonical S-expression atom: `<decimal_length>:<data>`.
fn atom(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data.len().to_string().as_bytes());
    buf.push(b':');
    buf.extend_from_slice(data);
}

fn open(buf: &mut Vec<u8>) {
    buf.push(b'(');
}

fn close(buf: &mut Vec<u8>) {
    buf.push(b')');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_p256_produces_correct_structure() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });

        let sexp = jwk_to_sexp(&jwk).unwrap();
        let prefix = b"(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:";
        let suffix = b")))";

        assert!(sexp.starts_with(prefix));
        assert!(sexp.ends_with(suffix));
        // 0x04 prefix byte for uncompressed point
        assert_eq!(sexp[prefix.len()], 0x04);
        assert_eq!(sexp.len(), prefix.len() + 65 + suffix.len());
    }

    #[test]
    fn ec_p384_uses_correct_curve_name() {
        let x_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 48]);
        let y_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 48]);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-384", "x": x_b64, "y": y_b64
        });

        let sexp = jwk_to_sexp(&jwk).unwrap();
        assert!(
            sexp.windows(b"NIST P-384".len())
                .any(|w| w == b"NIST P-384")
        );
    }

    #[test]
    fn ec_p521_uses_correct_curve_name() {
        let x_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 66]);
        let y_b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 66]);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-521", "x": x_b64, "y": y_b64
        });

        let sexp = jwk_to_sexp(&jwk).unwrap();
        assert!(
            sexp.windows(b"NIST P-521".len())
                .any(|w| w == b"NIST P-521")
        );
    }

    #[test]
    fn rsa_produces_correct_structure() {
        let n_b64 = URL_SAFE_NO_PAD.encode(vec![1u8; 256]);
        let e_b64 = URL_SAFE_NO_PAD.encode(vec![1, 0, 1]);
        let jwk = serde_json::json!({
            "kty": "RSA", "n": n_b64, "e": e_b64
        });

        let sexp = jwk_to_sexp(&jwk).unwrap();
        assert!(sexp.starts_with(b"(10:public-key(3:rsa(1:n"));
        assert!(sexp.ends_with(b")))"));
    }

    #[test]
    fn missing_kty_returns_error() {
        let jwk = serde_json::json!({"crv": "P-256"});
        assert!(jwk_to_sexp(&jwk).is_err());
    }

    #[test]
    fn unsupported_kty_returns_error() {
        let jwk = serde_json::json!({"kty": "OKP"});
        assert!(jwk_to_sexp(&jwk).is_err());
    }

    #[test]
    fn unsupported_ec_curve_returns_error() {
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "secp256k1",
            "x": "AAAA", "y": "AAAA"
        });
        assert!(jwk_to_sexp(&jwk).is_err());
    }

    #[test]
    fn missing_ec_field_returns_error() {
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "AAAA"
        });
        assert!(jwk_to_sexp(&jwk).is_err());
    }

    #[test]
    fn missing_rsa_field_returns_error() {
        let n_b64 = URL_SAFE_NO_PAD.encode(vec![1u8; 256]);
        let jwk = serde_json::json!({"kty": "RSA", "n": n_b64});
        assert!(jwk_to_sexp(&jwk).is_err());
    }
}
