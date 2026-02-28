use axum::Json;
use axum::extract::FromRequest;
use axum::http::Request;
use serde::Deserialize;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, decrypt_jwe_direct, decrypt_private_key,
    extract_kid, jwk_from_json, verify_jws,
};

use super::check_signing_key_not_expired;
use super::error::AuthError;

/// Authenticated list of (client_id, pairing_id) pairs from the request body.
#[derive(Debug, Clone)]
pub struct ClientJwtAuth {
    pub clients: Vec<ClientInfo>,
}

/// A single verified client identity.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub client_id: String,
    pub pairing_id: String,
}

#[derive(Debug, Deserialize)]
struct ClientJwtBody {
    client_jwts: Vec<String>,
}

impl FromRequest<AppState> for ClientJwtAuth {
    type Rejection = AppError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Json(body) = Json::<ClientJwtBody>::from_request(req, state)
            .await
            .map_err(|e| AppError::validation(format!("invalid request body: {e}")))?;

        if body.client_jwts.is_empty() {
            return Err(AuthError::Unauthorized("no client_jwts provided".into()).into());
        }

        let verified = verify_all_tokens(&body.client_jwts, state).await?;
        let filtered = filter_valid_pairings(verified, state).await?;

        if filtered.is_empty() {
            return Err(AuthError::Unauthorized("all client tokens filtered out".into()).into());
        }

        Ok(Self { clients: filtered })
    }
}

/// Verify and decrypt all tokens. Any crypto failure rejects ALL (all-or-nothing).
pub(crate) async fn verify_all_tokens(
    tokens: &[String],
    state: &AppState,
) -> Result<Vec<(String, String)>, AppError> {
    let mut pairs = Vec::with_capacity(tokens.len());
    for token in tokens {
        let (client_id, pairing_id) = verify_one_token(token, state).await?;
        pairs.push((client_id, pairing_id));
    }
    Ok(pairs)
}

/// Verify the outer JWS, decrypt the inner JWE, return (client_id, pairing_id).
pub(crate) async fn verify_one_token(
    token: &str,
    state: &AppState,
) -> Result<(String, String), AppError> {
    let kid = extract_kid(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let signing_key = state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(AppError::from)?
        .ok_or(AuthError::InvalidToken("unknown signing key".into()))?;

    check_signing_key_not_expired(&signing_key)?;

    let public_jwk = jwk_from_json(&signing_key.public_key)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let outer: ClientOuterClaims = verify_jws(token, &public_jwk, PayloadType::Client)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let inner = decrypt_inner_jwe(&outer.client_jwe, &signing_key.private_key, state)?;
    Ok((inner.sub, inner.pairing_id))
}

/// Decrypt the inner JWE to extract ClientInnerClaims.
pub(crate) fn decrypt_inner_jwe(
    jwe_token: &str,
    encrypted_private_key: &str,
    state: &AppState,
) -> Result<ClientInnerClaims, AppError> {
    let private_json = decrypt_private_key(encrypted_private_key, &state.signing_key_secret)
        .map_err(|e| AuthError::InvalidToken(format!("key decrypt failed: {e}")))?;
    let private_jwk = jwk_from_json(&private_json)
        .map_err(|e| AuthError::InvalidToken(format!("invalid private JWK: {e}")))?;

    let plaintext = decrypt_jwe_direct(jwe_token, &private_jwk)
        .map_err(|e| AuthError::InvalidToken(format!("JWE decryption failed: {e}")))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| AuthError::InvalidToken(format!("invalid inner claims: {e}")).into())
}

/// Filter out pairs whose pairing_id is not in client_pairings (soft failure).
///
/// Groups by client_id to avoid redundant DB queries when multiple tokens
/// share the same client.
pub(crate) async fn filter_valid_pairings(
    pairs: Vec<(String, String)>,
    state: &AppState,
) -> Result<Vec<ClientInfo>, AppError> {
    use std::collections::HashMap;

    // Group pairing_ids by client_id to deduplicate DB lookups.
    let mut by_client: HashMap<String, Vec<String>> = HashMap::new();
    for (client_id, pairing_id) in &pairs {
        by_client
            .entry(client_id.clone())
            .or_default()
            .push(pairing_id.clone());
    }

    // Fetch pairings once per unique client_id.
    let mut pairing_sets: HashMap<String, Vec<String>> = HashMap::new();
    for client_id in by_client.keys() {
        let db_pairings = state
            .repository
            .get_client_pairings(client_id)
            .await
            .map_err(AppError::from)?;
        pairing_sets.insert(
            client_id.clone(),
            db_pairings.into_iter().map(|p| p.pairing_id).collect(),
        );
    }

    // Filter original pairs preserving order.
    let valid = pairs
        .into_iter()
        .filter(|(cid, pid)| pairing_sets.get(cid).is_some_and(|ids| ids.contains(pid)))
        .map(|(client_id, pairing_id)| ClientInfo {
            client_id,
            pairing_id,
        })
        .collect();

    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{
        encrypt_jwe_direct, encrypt_private_key, generate_signing_key_pair, jwk_to_json, sign_jws,
    };
    use crate::repository::{
        ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
    };
    use async_trait::async_trait;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-secret-key!";

    // ---- Mock repository ----

    #[derive(Debug, Clone)]
    struct MockRepo {
        signing_key: Option<SigningKeyRow>,
        pairings: Vec<ClientPairingRow>,
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
        async fn get_client_pairings(
            &self,
            client_id: &str,
        ) -> anyhow::Result<Vec<ClientPairingRow>> {
            Ok(self
                .pairings
                .iter()
                .filter(|p| p.client_id == client_id)
                .cloned()
                .collect())
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
        async fn count_unconsumed_pairings(&self, _now: &str) -> anyhow::Result<i64> {
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
        async fn get_full_request_by_id(
            &self,
            _: &str,
        ) -> anyhow::Result<Option<crate::repository::FullRequestRow>> {
            unimplemented!()
        }
        async fn update_request_phase2(&self, _: &str, _: &str) -> anyhow::Result<bool> {
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

    fn make_client_jwt(
        priv_jwk: &josekit::jwk::Jwk,
        pub_jwk: &josekit::jwk::Jwk,
        kid: &str,
        client_id: &str,
        pairing_id: &str,
    ) -> String {
        let inner_claims = ClientInnerClaims {
            sub: client_id.into(),
            pairing_id: pairing_id.into(),
        };
        let inner_bytes = serde_json::to_vec(&inner_claims).unwrap();
        let jwe = encrypt_jwe_direct(&inner_bytes, pub_jwk).unwrap();

        let outer = ClientOuterClaims {
            payload_type: PayloadType::Client,
            client_jwe: jwe,
            exp: 1_900_000_000,
        };
        sign_jws(&outer, priv_jwk, kid).unwrap()
    }

    fn make_state(repo: MockRepo) -> AppState {
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
        }
    }

    async fn handler(_auth: ClientJwtAuth) -> Json<serde_json::Value> {
        Json(serde_json::json!({"ok": true}))
    }

    fn build_app(state: AppState) -> Router {
        Router::new()
            .route("/v1/tokens", post(handler))
            .with_state(state)
    }

    fn json_body(tokens: &[String]) -> Body {
        let body = serde_json::json!({ "client_jwts": tokens });
        Body::from(serde_json::to_vec(&body).unwrap())
    }

    // ---- Tests ----

    #[tokio::test]
    async fn valid_single_client_jwt_succeeds() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let pairing = ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            pairings: vec![pairing],
        };
        let app = build_app(make_state(repo));

        let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[token]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_verification_failure_rejects_all() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let pairing = ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            pairings: vec![pairing],
        };
        let app = build_app(make_state(repo));

        let valid_token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
        let bad_token = "invalid.jwt.token".to_owned();
        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[valid_token, bad_token]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pairing_not_found_filters_out() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        // No pairings in DB → all filtered out → 401
        let repo = MockRepo {
            signing_key: Some(sk),
            pairings: vec![],
        };
        let app = build_app(make_state(repo));

        let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[token]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_body_returns_401() {
        let repo = MockRepo {
            signing_key: None,
            pairings: vec![],
        };
        let app = build_app(make_state(repo));

        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn multiple_valid_tokens_returns_all() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let pairings = vec![
            ClientPairingRow {
                client_id: "fid-1".into(),
                pairing_id: "pair-1".into(),
                client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
            },
            ClientPairingRow {
                client_id: "fid-2".into(),
                pairing_id: "pair-2".into(),
                client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
            },
        ];
        let repo = MockRepo {
            signing_key: Some(sk),
            pairings,
        };
        let state = make_state(repo);
        let app = build_app(state);

        let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
        let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-2", "pair-2");
        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[t1, t2]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn expired_outer_jws_rejects_all() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
        let pairing = ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        };
        let repo = MockRepo {
            signing_key: Some(sk),
            pairings: vec![pairing],
        };
        let app = build_app(make_state(repo));

        // Create token with expired outer JWS
        let inner_claims = ClientInnerClaims {
            sub: "fid-1".into(),
            pairing_id: "pair-1".into(),
        };
        let inner_bytes = serde_json::to_vec(&inner_claims).unwrap();
        let jwe = encrypt_jwe_direct(&inner_bytes, &pub_jwk).unwrap();
        let outer = ClientOuterClaims {
            payload_type: PayloadType::Client,
            client_jwe: jwe,
            exp: 1_000_000_000, // past
        };
        let token = sign_jws(&outer, &priv_jwk, &kid).unwrap();

        let response = app
            .oneshot(
                Request::post("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(json_body(&[token]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
