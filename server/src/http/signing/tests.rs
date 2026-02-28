use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use axum::routing::post;
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::fcm::NoopFcmValidator;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, encrypt_jwe_direct, encrypt_private_key,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{
    AuditLogRow, ClientPairingRow, ClientRow, CreateRequestRow, PairingRow, RequestRow,
    SignatureRepository, SigningKeyRow,
};

use super::handler::{build_e2e_kids_map, build_pairing_ids_map, compute_expiry};
use super::post_sign_request;
use super::types::E2eKeyItem;

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SigningMockRepo {
    signing_key: Option<SigningKeyRow>,
    clients: Mutex<Vec<ClientRow>>,
    client_pairings: Mutex<Vec<ClientPairingRow>>,
    pending_count: i64,
    requests: Mutex<Vec<CreateRequestRow>>,
    audit_logs: Mutex<Vec<AuditLogRow>>,
    jti_accepted: bool,
    force_create_request_error: bool,
    force_audit_log_error: bool,
}

impl SigningMockRepo {
    fn new(signing_key: SigningKeyRow) -> Self {
        Self {
            signing_key: Some(signing_key),
            clients: Mutex::new(Vec::new()),
            client_pairings: Mutex::new(Vec::new()),
            pending_count: 0,
            requests: Mutex::new(Vec::new()),
            audit_logs: Mutex::new(Vec::new()),
            jti_accepted: true,
            force_create_request_error: false,
            force_audit_log_error: false,
        }
    }
}

#[async_trait]
impl SignatureRepository for SigningMockRepo {
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
    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
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
    async fn update_client_device_token(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        Ok(self
            .client_pairings
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.client_id == client_id)
            .cloned()
            .collect())
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
    async fn update_client_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_pairing(&self, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_pairing_by_id(&self, _: &str) -> anyhow::Result<Option<PairingRow>> {
        Ok(None)
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
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(None)
    }
    async fn create_request(&self, row: &CreateRequestRow) -> anyhow::Result<()> {
        if self.force_create_request_error {
            anyhow::bail!("forced create_request error");
        }
        self.requests.lock().unwrap().push(row.clone());
        Ok(())
    }
    async fn count_pending_requests_for_pairing(
        &self,
        _client_id: &str,
        _pairing_id: &str,
    ) -> anyhow::Result<i64> {
        Ok(self.pending_count)
    }
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()> {
        if self.force_audit_log_error {
            anyhow::bail!("forced audit_log error");
        }
        self.audit_logs.lock().unwrap().push(row.clone());
        Ok(())
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
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(self.jti_accepted)
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET: &str = "test-secret-key!";
const VALID_COORD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
    let inner = ClientInnerClaims {
        sub: client_id.into(),
        pairing_id: pairing_id.into(),
    };
    let inner_bytes = serde_json::to_vec(&inner).unwrap();
    let jwe = encrypt_jwe_direct(&inner_bytes, pub_jwk).unwrap();
    let outer = ClientOuterClaims {
        payload_type: PayloadType::Client,
        client_jwe: jwe,
        exp: 1_900_000_000,
    };
    sign_jws(&outer, priv_jwk, kid).unwrap()
}

fn make_client_row_with_enc_key(client_id: &str, enc_kid: &str) -> ClientRow {
    let enc_key = json!({
        "kid": enc_kid,
        "kty": "EC",
        "crv": "P-256",
        "x": VALID_COORD,
        "y": VALID_COORD,
        "use": "enc",
        "alg": "ECDH-ES+A256KW"
    });
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: serde_json::to_string(&vec![enc_key]).unwrap(),
        default_kid: enc_kid.to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}

fn make_client_row_no_enc_key(client_id: &str) -> ClientRow {
    let sig_key = json!({
        "kid": "sig-kid",
        "kty": "EC",
        "crv": "P-256",
        "x": VALID_COORD,
        "y": VALID_COORD,
        "use": "sig",
        "alg": "ES256"
    });
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: serde_json::to_string(&vec![sig_key]).unwrap(),
        default_kid: "sig-kid".to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}

fn make_state(repo: SigningMockRepo) -> AppState {
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
        fcm_validator: Arc::new(NoopFcmValidator),
        sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
    }
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", post(post_sign_request))
        .with_state(state)
}

fn valid_request_body(client_jwts: Vec<String>) -> serde_json::Value {
    json!({
        "client_jwts": client_jwts,
        "daemon_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        },
        "daemon_enc_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ECDH-ES+A256KW"
        }
    })
}

fn post_json(body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/sign-request")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn response_status(app: Router, req: Request<Body>) -> StatusCode {
    app.oneshot(req).await.unwrap().status()
}

/// Setup common test fixtures: signing key pair, mock repo with a client + pairing.
fn setup_happy_path() -> (
    josekit::jwk::Jwk,
    josekit::jwk::Jwk,
    String,
    SigningMockRepo,
) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = SigningMockRepo::new(sk);

    repo.client_pairings.lock().unwrap().push(ClientPairingRow {
        client_id: "client-1".into(),
        pairing_id: "pair-1".into(),
        client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
    });

    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row_with_enc_key("client-1", "enc-kid-1"));

    (priv_jwk, pub_jwk, kid, repo)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_returns_201_with_request_jwt_and_e2e_keys() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let state = make_state(repo);
    let app = build_app(state);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let resp = app.oneshot(post_json(&body)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("request_jwt").is_some());
    assert!(json.get("e2e_keys").is_some());

    let e2e_keys = json["e2e_keys"].as_array().unwrap();
    assert_eq!(e2e_keys.len(), 1);
    assert_eq!(e2e_keys[0]["client_id"], "client-1");
}

#[tokio::test]
async fn happy_path_persists_request_and_audit_log() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo_arc: Arc<SigningMockRepo> = Arc::new(repo);
    let state = {
        use crate::http::pairing::notifier::PairingNotifier;
        use crate::http::rate_limit::{SseConnectionTracker, config::SseConnectionConfig};
        AppState {
            repository: repo_arc.clone(),
            base_url: "https://api.example.com".to_owned(),
            signing_key_secret: TEST_SECRET.to_owned(),
            device_jwt_validity_seconds: 31_536_000,
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            fcm_validator: Arc::new(NoopFcmValidator),
            sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
                max_per_ip: 20,
                max_per_key: 1,
            }),
            pairing_notifier: PairingNotifier::new(),
        }
    };
    let app = build_app(state);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::CREATED);

    assert_eq!(repo_arc.requests.lock().unwrap().len(), 1);
    assert_eq!(repo_arc.audit_logs.lock().unwrap().len(), 1);

    let req_row = &repo_arc.requests.lock().unwrap()[0];
    assert_eq!(req_row.status, "created");
    assert!(!req_row.request_id.is_empty());

    let log_row = &repo_arc.audit_logs.lock().unwrap()[0];
    assert_eq!(log_row.event_type, "sign_request_created");
}

#[tokio::test]
async fn empty_client_jwts_returns_401() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let body = valid_request_body(vec![]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_daemon_public_key_returns_400() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "RSA",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        },
        "daemon_enc_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ECDH-ES+A256KW"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_daemon_enc_public_key_returns_400() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        },
        "daemon_enc_public_key": {
            "kty": "EC",
            "crv": "P-384",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ECDH-ES+A256KW"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rate_limit_exceeded_returns_429() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = SigningMockRepo {
        pending_count: 5,
        ..repo
    };
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_active_signing_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let sk = repo.signing_key.clone().unwrap();
    let repo = NoActiveKeyMockRepo {
        base: repo,
        verification_key: Some(sk),
    };
    let state = {
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
            fcm_validator: Arc::new(NoopFcmValidator),
            sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
                max_per_ip: 20,
                max_per_key: 1,
            }),
            pairing_notifier: PairingNotifier::new(),
        }
    };
    let app = build_app(state);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn client_not_in_db_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Remove client row so lookup_enc_key returns None → empty e2e_keys → 500.
    repo.clients.lock().unwrap().clear();
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn client_without_enc_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Replace client with one that has no enc key → empty e2e_keys → 500.
    repo.clients.lock().unwrap().clear();
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row_no_enc_key("client-1"));
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn multiple_clients_happy_path() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = SigningMockRepo::new(sk);

    for (cid, pid) in &[("c1", "p1"), ("c2", "p2")] {
        repo.client_pairings.lock().unwrap().push(ClientPairingRow {
            client_id: cid.to_string(),
            pairing_id: pid.to_string(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        repo.clients
            .lock()
            .unwrap()
            .push(make_client_row_with_enc_key(cid, &format!("ek-{cid}")));
    }

    let app = build_app(make_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "c1", "p1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "c2", "p2");
    let body = valid_request_body(vec![t1, t2]);
    let resp = app.oneshot(post_json(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    let e2e_keys = json["e2e_keys"].as_array().unwrap();
    assert_eq!(e2e_keys.len(), 2);
}

#[tokio::test]
async fn create_request_error_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = SigningMockRepo {
        force_create_request_error: true,
        ..repo
    };
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn audit_log_error_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = SigningMockRepo {
        force_audit_log_error: true,
        ..repo
    };
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn invalid_jwt_token_returns_401() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let body = valid_request_body(vec!["not.a.valid.jwt".to_owned()]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairing_not_in_db_returns_401() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Remove pairings so filter_valid_pairings filters all out.
    repo.client_pairings.lock().unwrap().clear();
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_below_threshold_passes() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = SigningMockRepo {
        pending_count: 4, // below MAX_PENDING_REQUESTS_PER_PAIRING (5)
        ..repo
    };
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let req = Request::builder()
        .method("POST")
        .uri("/sign-request")
        .header("content-type", "application/json")
        .body(Body::from(b"not json".to_vec()))
        .unwrap();
    let status = response_status(app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_daemon_enc_public_key_returns_422() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Specialised mock: returns signing key for verification but None for active.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoActiveKeyMockRepo {
    base: SigningMockRepo,
    verification_key: Option<SigningKeyRow>,
}

#[async_trait]
impl SignatureRepository for NoActiveKeyMockRepo {
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
        Ok(None) // <-- no active key
    }
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        Ok(self
            .verification_key
            .as_ref()
            .filter(|k| k.kid == kid)
            .cloned())
    }
    async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
        unimplemented!()
    }
    async fn get_client_by_id(&self, id: &str) -> anyhow::Result<Option<ClientRow>> {
        self.base.get_client_by_id(id).await
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
    async fn update_client_device_token(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        self.base.get_client_pairings(id).await
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
    async fn update_client_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_pairing(&self, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_pairing_by_id(&self, _: &str) -> anyhow::Result<Option<PairingRow>> {
        Ok(None)
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
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(None)
    }
    async fn create_request(&self, r: &CreateRequestRow) -> anyhow::Result<()> {
        self.base.create_request(r).await
    }
    async fn count_pending_requests_for_pairing(&self, c: &str, p: &str) -> anyhow::Result<i64> {
        self.base.count_pending_requests_for_pairing(c, p).await
    }
    async fn create_audit_log(&self, r: &AuditLogRow) -> anyhow::Result<()> {
        self.base.create_audit_log(r).await
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
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Helper to extract JSON from response.
// ---------------------------------------------------------------------------

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Unit tests for pure helpers (moved from handler.rs)
// ---------------------------------------------------------------------------

#[test]
fn e2e_kids_map_built_correctly() {
    let items = vec![
        E2eKeyItem {
            client_id: "c1".into(),
            public_key: serde_json::json!({"kid": "k1", "use": "enc"}),
        },
        E2eKeyItem {
            client_id: "c2".into(),
            public_key: serde_json::json!({"kid": "k2", "use": "enc"}),
        },
    ];
    let map = build_e2e_kids_map(&items);
    assert_eq!(map.get("c1").unwrap().as_str().unwrap(), "k1");
    assert_eq!(map.get("c2").unwrap().as_str().unwrap(), "k2");
}

#[test]
fn e2e_kids_map_skips_missing_kid() {
    let items = vec![E2eKeyItem {
        client_id: "c1".into(),
        public_key: serde_json::json!({"use": "enc"}),
    }];
    let map = build_e2e_kids_map(&items);
    assert!(map.as_object().unwrap().is_empty());
}

#[test]
fn pairing_ids_map_built_correctly() {
    use crate::http::auth::ClientInfo;

    let clients = vec![
        ClientInfo {
            client_id: "c1".into(),
            pairing_id: "p1".into(),
        },
        ClientInfo {
            client_id: "c2".into(),
            pairing_id: "p2".into(),
        },
    ];
    let map = build_pairing_ids_map(&clients);
    assert_eq!(map.get("c1").unwrap().as_str().unwrap(), "p1");
    assert_eq!(map.get("c2").unwrap().as_str().unwrap(), "p2");
}

#[test]
fn compute_expiry_returns_rfc3339() {
    let exp = compute_expiry(300);
    chrono::DateTime::parse_from_rfc3339(&exp).expect("should be valid RFC 3339");
}
