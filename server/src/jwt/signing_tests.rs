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

    let result: anyhow::Result<DeviceClaims> = verify_jws(&token, &other_pub, PayloadType::Device);
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

    let result: anyhow::Result<DeviceClaims> = verify_jws(&token, &pub_jwk, PayloadType::Client);
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
    let result: anyhow::Result<DeviceClaims> = verify_jws(&token, &pub_jwk, PayloadType::Device);
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
