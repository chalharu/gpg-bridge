use serde::{Deserialize, Serialize};

/// Identifies the type of a JWT payload for dispatch and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    Device,
    Client,
    Pairing,
    Request,
    Sign,
}

impl PayloadType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Client => "client",
            Self::Pairing => "pairing",
            Self::Request => "request",
            Self::Sign => "sign",
        }
    }
}

/// device_jwt claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceClaims {
    pub sub: String,
    pub payload_type: PayloadType,
    pub exp: i64,
}

/// client_jwt outer JWS claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientOuterClaims {
    pub payload_type: PayloadType,
    pub client_jwe: String,
    pub exp: i64,
}

/// client_jwt inner JWE plaintext claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientInnerClaims {
    pub sub: String,
    pub pairing_id: String,
}

/// pairing_jwt claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingClaims {
    pub sub: String,
    pub payload_type: PayloadType,
    pub exp: i64,
}

/// request_jwt claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestClaims {
    pub sub: String,
    pub payload_type: PayloadType,
    pub exp: i64,
}

/// sign_jwt claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignClaims {
    pub sub: String,
    pub client_id: String,
    pub payload_type: PayloadType,
    pub exp: i64,
}

/// device_assertion_jwt claims (used by DeviceAssertionAuth extractor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceAssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

/// daemon_auth_jws outer claims (used by DaemonAuthJws extractor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonAuthClaims {
    pub request_jwt: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_type_serializes_to_snake_case() {
        let json = serde_json::to_string(&PayloadType::Device).unwrap();
        assert_eq!(json, "\"device\"");
        let json = serde_json::to_string(&PayloadType::Client).unwrap();
        assert_eq!(json, "\"client\"");
        let json = serde_json::to_string(&PayloadType::Sign).unwrap();
        assert_eq!(json, "\"sign\"");
    }

    #[test]
    fn payload_type_deserializes_from_snake_case() {
        let pt: PayloadType = serde_json::from_str("\"pairing\"").unwrap();
        assert_eq!(pt, PayloadType::Pairing);
        let pt: PayloadType = serde_json::from_str("\"request\"").unwrap();
        assert_eq!(pt, PayloadType::Request);
    }

    #[test]
    fn payload_type_as_str_matches_serde() {
        for pt in [
            PayloadType::Device,
            PayloadType::Client,
            PayloadType::Pairing,
            PayloadType::Request,
            PayloadType::Sign,
        ] {
            let json = serde_json::to_string(&pt).unwrap();
            assert_eq!(json, format!("\"{}\"", pt.as_str()));
        }
    }

    #[test]
    fn device_claims_roundtrip() {
        let claims = DeviceClaims {
            sub: "fid-123".into(),
            payload_type: PayloadType::Device,
            exp: 1_700_000_000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: DeviceClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn client_outer_claims_roundtrip() {
        let claims = ClientOuterClaims {
            payload_type: PayloadType::Client,
            client_jwe: "jwe-token".into(),
            exp: 1_700_000_000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: ClientOuterClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn client_inner_claims_roundtrip() {
        let claims = ClientInnerClaims {
            sub: "fid-456".into(),
            pairing_id: "pair-uuid".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: ClientInnerClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn sign_claims_roundtrip() {
        let claims = SignClaims {
            sub: "req-uuid".into(),
            client_id: "fid-789".into(),
            payload_type: PayloadType::Sign,
            exp: 1_700_000_000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: SignClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn pairing_claims_roundtrip() {
        let claims = PairingClaims {
            sub: "fid-pair".into(),
            payload_type: PayloadType::Pairing,
            exp: 1_700_000_000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: PairingClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn request_claims_roundtrip() {
        let claims = RequestClaims {
            sub: "fid-req".into(),
            payload_type: PayloadType::Request,
            exp: 1_700_000_000,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: RequestClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn device_assertion_claims_roundtrip() {
        let claims = DeviceAssertionClaims {
            iss: "fid-1".into(),
            sub: "fid-1".into(),
            aud: "https://api.example.com/sign".into(),
            exp: 1_900_000_000,
            iat: 1_900_000_000 - 30,
            jti: "jti-uuid".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: DeviceAssertionClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn daemon_auth_claims_roundtrip() {
        let claims = DaemonAuthClaims {
            request_jwt: "inner.jwt.token".into(),
            aud: "https://api.example.com/sign".into(),
            iat: 1_900_000_000 - 30,
            exp: 1_900_000_000,
            jti: "jti-uuid".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let back: DaemonAuthClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }
}
