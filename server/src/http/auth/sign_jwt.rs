use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{PayloadType, SignClaims, extract_kid, jwk_from_json, verify_jws};

use super::error::AuthError;
use super::{check_signing_key_not_expired, extract_bearer_token};

/// Authenticated sign identity extracted from `Authorization: Bearer <sign_jwt>`.
///
/// The sign_jwt is a JWS issued by the server (not a device), so verification
/// uses the server's signing keys.
#[derive(Debug, Clone)]
pub struct SignJwtAuth {
    pub request_id: String,
    pub client_id: String,
}

impl FromRequestParts<AppState> for SignJwtAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let kid = extract_kid(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let signing_key = state
            .repository
            .get_signing_key_by_kid(&kid)
            .await
            .map_err(AppError::from)?
            .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

        check_signing_key_not_expired(&signing_key)?;

        let public_jwk = jwk_from_json(&signing_key.public_key)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let claims: SignClaims = verify_jws(&token, &public_jwk, PayloadType::Sign)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(Self {
            request_id: claims.sub,
            client_id: claims.client_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json, sign_jws};
    use crate::repository::{
        ClientPairingRow, ClientRow, FullRequestRow, RequestRow, SignatureRepository, SigningKeyRow,
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
            Ok(None)
        }
        async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            Ok(true)
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
        async fn create_pairing(&self, _: &str, _: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_pairing_by_id(
            &self,
            _: &str,
        ) -> anyhow::Result<Option<crate::repository::PairingRow>> {
            unimplemented!()
        }
        async fn consume_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn count_unconsumed_pairings(&self, _: &str) -> anyhow::Result<i64> {
            unimplemented!()
        }
        async fn delete_expired_pairings(&self, _: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn create_client_pairing(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_client_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_client_pairing_and_cleanup(
            &self,
            _: &str,
            _: &str,
        ) -> anyhow::Result<(bool, bool)> {
            unimplemented!()
        }
        async fn update_client_jwt_issued_at(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn create_request(
            &self,
            _: &crate::repository::CreateRequestRow,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn count_pending_requests_for_pairing(
            &self,
            _: &str,
            _: &str,
        ) -> anyhow::Result<i64> {
            unimplemented!()
        }
        async fn create_audit_log(&self, _: &crate::repository::AuditLogRow) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn delete_expired_audit_logs(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn get_full_request_by_id(&self, _: &str) -> anyhow::Result<Option<FullRequestRow>> {
            unimplemented!()
        }
        async fn update_request_phase2(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn get_pending_requests_for_client(
            &self,
            _: &str,
        ) -> anyhow::Result<Vec<FullRequestRow>> {
            unimplemented!()
        }
        async fn update_request_approved(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn update_request_denied(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn add_unavailable_client_id(
            &self,
            _: &str,
            _: &str,
        ) -> anyhow::Result<Option<(String, String)>> {
            unimplemented!()
        }
        async fn update_request_unavailable(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_request(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_requests(&self, _: &str) -> anyhow::Result<Vec<String>> {
            unimplemented!()
        }
        async fn delete_unpaired_clients(&self, _: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn delete_expired_device_jwt_clients(&self, _: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn delete_expired_client_jwt_pairings(&self, _: &str) -> anyhow::Result<u64> {
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

    fn make_state(repo: impl SignatureRepository + 'static) -> AppState {
        use crate::http::pairing::notifier::PairingNotifier;
        use crate::http::rate_limit::{SseConnectionTracker, config::SseConnectionConfig};

        AppState {
            repository: Arc::new(repo),
            base_url: "https://api.example.com".to_owned(),
            signing_key_secret: TEST_SECRET.to_owned(),
            device_jwt_validity_seconds: 31_536_000,
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            fcm_validator: Arc::new(crate::http::fcm::NoopFcmValidator),
            fcm_sender: Arc::new(crate::http::fcm::NoopFcmSender),
            sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
                max_per_ip: 20,
                max_per_key: 1,
            }),
            pairing_notifier: PairingNotifier::new(),
            sign_event_notifier: crate::http::signing::notifier::SignEventNotifier::new(),
        }
    }

    async fn handler(_auth: SignJwtAuth) -> Json<String> {
        Json("ok".into())
    }

    fn build_app(state: AppState) -> Router {
        Router::new()
            .route("/sign-result", get(handler))
            .with_state(state)
    }

    fn make_sign_jwt(
        priv_jwk: &josekit::jwk::Jwk,
        kid: &str,
        request_id: &str,
        client_id: &str,
    ) -> String {
        let claims = SignClaims {
            sub: request_id.into(),
            client_id: client_id.into(),
            payload_type: PayloadType::Sign,
            exp: 1_900_000_000,
        };
        sign_jws(&claims, priv_jwk, kid).unwrap()
    }

    // ---- Tests ----

    #[tokio::test]
    async fn valid_sign_jwt_succeeds() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let state = make_state(MockRepo {
            signing_key: Some(sk),
        });
        let app = build_app(state);

        let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
        let response = app
            .oneshot(
                Request::get("/sign-result")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = make_state(MockRepo { signing_key: None });
        let app = build_app(state);

        let response = app
            .oneshot(Request::get("/sign-result").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_key_returns_401() {
        let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let (_other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &other_pub, &other_kid);
        let state = make_state(MockRepo {
            signing_key: Some(sk),
        });
        let app = build_app(state);

        let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
        let response = app
            .oneshot(
                Request::get("/sign-result")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_sign_jwt_returns_401() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let state = make_state(MockRepo {
            signing_key: Some(sk),
        });
        let app = build_app(state);

        let claims = SignClaims {
            sub: "req-1".into(),
            client_id: "client-1".into(),
            payload_type: PayloadType::Sign,
            exp: 1_000_000_000, // past
        };
        let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

        let response = app
            .oneshot(
                Request::get("/sign-result")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_signing_key_returns_401() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let mut sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        sk.expires_at = "2020-01-01T00:00:00Z".into(); // expired key
        let state = make_state(MockRepo {
            signing_key: Some(sk),
        });
        let app = build_app(state);

        let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
        let response = app
            .oneshot(
                Request::get("/sign-result")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
