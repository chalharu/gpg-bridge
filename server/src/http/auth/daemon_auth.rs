use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, PayloadType, RequestClaims, decode_jws_unverified, extract_kid,
    jwk_from_json, verify_jws, verify_jws_with_key,
};

use super::error::AuthError;
use super::{
    build_expected_aud, check_signing_key_not_expired, extract_bearer_token, timestamp_to_rfc3339,
};

/// Authenticated request identity from daemon `Authorization: Bearer`.
#[derive(Debug, Clone)]
pub struct DaemonAuthJws {
    pub request_id: String,
}

impl FromRequestParts<AppState> for DaemonAuthJws {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;

        // Step 1: Decode outer JWS (unverified) to get request_jwt
        let outer: DaemonAuthClaims =
            decode_jws_unverified(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Steps 2-3: Verify inner request_jwt with server signing key
        let request_claims = verify_request_jwt(&outer.request_jwt, state).await?;
        let request_id = &request_claims.sub;

        // Step 4: Fetch daemon_public_key from DB
        let daemon_pub_jwk = fetch_daemon_key(state, request_id).await?;

        // Step 5: Verify outer JWS with daemon_public_key
        let verified: DaemonAuthClaims = verify_jws_with_key(&token, &daemon_pub_jwk)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Step 6: Check aud
        let expected_aud = build_expected_aud(&state.base_url, parts);
        validate_aud(&verified, &expected_aud)?;

        // Step 7: Check jti replay
        store_jti(state, &verified.jti, verified.exp).await?;

        Ok(Self {
            request_id: request_id.clone(),
        })
    }
}

/// Verify the inner `request_jwt` using the server's signing key.
async fn verify_request_jwt(
    request_jwt: &str,
    state: &AppState,
) -> Result<RequestClaims, AppError> {
    let kid = extract_kid(request_jwt).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    verify_jws(request_jwt, &public_jwk, PayloadType::Request)
        .map_err(|e| AuthError::InvalidToken(e.to_string()).into())
}

/// Fetch the daemon public key from the requests table.
async fn fetch_daemon_key(
    state: &AppState,
    request_id: &str,
) -> Result<josekit::jwk::Jwk, AppError> {
    let request = state
        .repository
        .get_request_by_id(request_id)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::Unauthorized("request not found".into()))?;

    jwk_from_json(&request.daemon_public_key)
        .map_err(|e| AuthError::InvalidToken(format!("invalid daemon_public_key: {e}")).into())
}

fn validate_aud(claims: &DaemonAuthClaims, expected: &str) -> Result<(), AuthError> {
    if claims.aud != expected {
        return Err(AuthError::InvalidToken("aud mismatch".into()));
    }
    Ok(())
}

async fn store_jti(state: &AppState, jti: &str, exp: i64) -> Result<(), AppError> {
    let expired = timestamp_to_rfc3339(exp)?;
    let stored = state
        .repository
        .store_jti(jti, &expired)
        .await
        .map_err(AppError::from)?;
    if !stored {
        return Err(AuthError::InvalidToken("jti replay detected".into()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json, sign_jws};
    use crate::repository::{
        ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use axum::{Json, Router};
    use std::sync::Arc;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-secret-key!";

    // ---- Mock repository ----

    #[derive(Debug, Clone)]
    struct MockRepo {
        signing_key: Option<SigningKeyRow>,
        request: Option<RequestRow>,
        jti_accepted: bool,
    }

    #[async_trait]
    impl SignatureRepository for MockRepo {
        async fn run_migrations(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn backend_name(&self) -> &'static str {
            "mock"
        }
        async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
            Ok(self.signing_key.clone())
        }
        async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
            Ok(self.signing_key.as_ref().filter(|k| k.kid == kid).cloned())
        }
        async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn get_client_by_id(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
            Ok(None)
        }
        async fn get_client_pairings(&self, _: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
            Ok(vec![])
        }
        async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
            Ok(self.request.clone())
        }
        async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            Ok(self.jti_accepted)
        }
        async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
            Ok(0)
        }
        async fn create_client(&self, _: &ClientRow) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn client_exists(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn client_by_device_token(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
            unimplemented!()
        }
        async fn update_client_device_token(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn update_device_jwt_issued_at(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn update_client_public_keys(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn update_client_gpg_keys(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn is_kid_in_flight(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
    }

    // ---- Helpers ----

    fn make_signing_key_row(
        priv_jwk: &josekit::jwk::Jwk,
        pub_jwk: &josekit::jwk::Jwk,
        kid: &str,
    ) -> SigningKeyRow {
        let private_json = jwk_to_json(priv_jwk).unwrap();
        let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
        SigningKeyRow {
            kid: kid.to_owned(),
            private_key: encrypted,
            public_key: jwk_to_json(pub_jwk).unwrap(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            is_active: true,
        }
    }

    fn make_state(repo: MockRepo) -> AppState {
        AppState {
            repository: Arc::new(repo),
            base_url: "https://api.example.com".to_owned(),
            signing_key_secret: TEST_SECRET.to_owned(),
            device_jwt_validity_seconds: 31_536_000,
            fcm_validator: Arc::new(crate::http::fcm::NoopFcmValidator),
        }
    }

    async fn handler(_auth: DaemonAuthJws) -> Json<String> {
        Json("ok".into())
    }

    fn build_app(state: AppState) -> Router {
        Router::new()
            .route("/v1/sign", get(handler))
            .with_state(state)
    }

    /// Create a valid daemon_auth_jws token:
    /// 1. Sign a request_jwt with the server's key
    /// 2. Sign the outer JWS with the daemon's key
    fn make_daemon_token(
        server_priv: &josekit::jwk::Jwk,
        server_kid: &str,
        daemon_priv: &josekit::jwk::Jwk,
        daemon_kid: &str,
        request_id: &str,
        aud: &str,
    ) -> String {
        let request_claims = RequestClaims {
            sub: request_id.into(),
            payload_type: PayloadType::Request,
            exp: 1_900_000_000,
        };
        let request_jwt = sign_jws(&request_claims, server_priv, server_kid).unwrap();

        let outer_claims = DaemonAuthClaims {
            request_jwt,
            aud: aud.into(),
            iat: 1_900_000_000 - 30,
            exp: 1_900_000_000,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        sign_jws(&outer_claims, daemon_priv, daemon_kid).unwrap()
    }

    // ---- Tests ----

    #[tokio::test]
    async fn valid_daemon_auth_succeeds() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        let token = make_daemon_token(
            &server_priv,
            &server_kid,
            &daemon_priv,
            &daemon_kid,
            "req-1",
            "https://api.example.com/v1/sign",
        );

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let repo = MockRepo {
            signing_key: None,
            request: None,
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        let response = app
            .oneshot(Request::get("/v1/sign").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_daemon_key_returns_401() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, _daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();
        let (_wrong_priv, wrong_pub, _wrong_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        // DB has wrong_pub as daemon key, but token is signed with daemon_priv
        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&wrong_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        let token = make_daemon_token(
            &server_priv,
            &server_kid,
            &daemon_priv,
            &daemon_kid,
            "req-1",
            "https://api.example.com/v1/sign",
        );

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_not_found_returns_401() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, _daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        let repo = MockRepo {
            signing_key: Some(sk),
            request: None, // not found
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        let token = make_daemon_token(
            &server_priv,
            &server_kid,
            &daemon_priv,
            &daemon_kid,
            "req-1",
            "https://api.example.com/v1/sign",
        );

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_aud_returns_401() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        let token = make_daemon_token(
            &server_priv,
            &server_kid,
            &daemon_priv,
            &daemon_kid,
            "req-1",
            "https://wrong.example.com/v1/sign", // wrong aud
        );

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jti_replay_returns_401() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: false, // replay
        };
        let app = build_app(make_state(repo));

        let token = make_daemon_token(
            &server_priv,
            &server_kid,
            &daemon_priv,
            &daemon_kid,
            "req-1",
            "https://api.example.com/v1/sign",
        );

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_outer_jws_returns_401() {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        // Create token with expired outer JWS
        let request_claims = RequestClaims {
            sub: "req-1".into(),
            payload_type: PayloadType::Request,
            exp: 1_900_000_000,
        };
        let request_jwt = sign_jws(&request_claims, &server_priv, &server_kid).unwrap();
        let outer = DaemonAuthClaims {
            request_jwt,
            aud: "https://api.example.com/v1/sign".into(),
            iat: 1_000_000_000 - 30,
            exp: 1_000_000_000, // past
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = sign_jws(&outer, &daemon_priv, &daemon_kid).unwrap();

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_request_jwt_returns_401() {
        let (_server_priv, _server_pub, _server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

        // Use a different server key for signing the request_jwt (wrong key)
        let (other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&other_priv, &other_pub, &other_kid);

        let request = RequestRow {
            request_id: "req-1".into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            request: Some(request),
            jti_accepted: true,
        };
        let app = build_app(make_state(repo));

        // request_jwt signed with _server_priv but DB has other_pub
        let request_claims = RequestClaims {
            sub: "req-1".into(),
            payload_type: PayloadType::Request,
            exp: 1_900_000_000,
        };
        // Sign with _server_priv but extract_kid will return _server_kid,
        // which won't match other_kid in the DB.
        // So let's sign with other_priv but wrong payload type so it fails
        // Actually, let's use a scenario where the kid doesn't match:
        let request_jwt = sign_jws(&request_claims, &daemon_priv, &daemon_kid).unwrap();
        let outer = DaemonAuthClaims {
            request_jwt,
            aud: "https://api.example.com/v1/sign".into(),
            iat: 1_900_000_000 - 30,
            exp: 1_900_000_000,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = sign_jws(&outer, &daemon_priv, &daemon_kid).unwrap();

        let response = app
            .oneshot(
                Request::get("/v1/sign")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
