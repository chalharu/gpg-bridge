use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use axum::routing::{delete, get, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::fcm::NoopFcmValidator;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, DeviceAssertionClaims, PairingClaims, PayloadType,
    encrypt_jwe_direct, encrypt_private_key, generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{
    ClientPairingRow, ClientRow, PairingRow, RequestRow, SignatureRepository, SigningKeyRow,
};

use super::helpers::{
    build_client_jwt_token, remove_pairing_and_cleanup, verify_pairing_ownership,
};
use super::{
    delete_pairing_by_daemon, delete_pairing_by_phone, get_pairing_token, pair_device,
    query_gpg_keys, refresh_client_jwt,
};

// ---------------------------------------------------------------------------
// Mock repository (single configurable mock for all pairing tests)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PairingMockRepo {
    signing_key: Option<SigningKeyRow>,
    clients: Mutex<Vec<ClientRow>>,
    pairings: Mutex<Vec<PairingRow>>,
    client_pairings_data: Mutex<Vec<ClientPairingRow>>,
    jti_accepted: bool,
    forced_unconsumed_count: Option<i64>,
    forced_errors: Mutex<HashSet<String>>,
    force_update_false: bool,
    signing_key_by_kid_call_count: AtomicUsize,
    signing_key_by_kid_max_success: Option<usize>,
}

impl PairingMockRepo {
    fn new(signing_key: SigningKeyRow) -> Self {
        Self {
            signing_key: Some(signing_key),
            clients: Mutex::new(Vec::new()),
            pairings: Mutex::new(Vec::new()),
            client_pairings_data: Mutex::new(Vec::new()),
            jti_accepted: true,
            forced_unconsumed_count: None,
            forced_errors: Mutex::new(HashSet::new()),
            force_update_false: false,
            signing_key_by_kid_call_count: AtomicUsize::new(0),
            signing_key_by_kid_max_success: None,
        }
    }

    fn force_error(&self, method: &str) {
        self.forced_errors.lock().unwrap().insert(method.to_owned());
    }

    fn check_forced_error(&self, method: &str) -> anyhow::Result<()> {
        if self.forced_errors.lock().unwrap().contains(method) {
            anyhow::bail!("forced test error for {method}");
        }
        Ok(())
    }
}

#[async_trait]
impl SignatureRepository for PairingMockRepo {
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
        self.check_forced_error("get_active_signing_key")?;
        Ok(self.signing_key.clone())
    }
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        self.check_forced_error("get_signing_key_by_kid")?;
        if let Some(max) = self.signing_key_by_kid_max_success {
            let count = self
                .signing_key_by_kid_call_count
                .fetch_add(1, Ordering::SeqCst);
            if count >= max {
                return Ok(None);
            }
        }
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
    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        self.clients
            .lock()
            .unwrap()
            .retain(|c| c.client_id != client_id);
        Ok(())
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        self.check_forced_error("get_client_pairings")?;
        Ok(self
            .client_pairings_data
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.client_id == client_id)
            .cloned()
            .collect())
    }
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(None)
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
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        self.check_forced_error("create_pairing")?;
        self.pairings.lock().unwrap().push(PairingRow {
            pairing_id: pairing_id.to_owned(),
            expired: expired.to_owned(),
            client_id: None,
        });
        Ok(())
    }
    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        self.check_forced_error("get_pairing_by_id")?;
        Ok(self
            .pairings
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.pairing_id == pairing_id)
            .cloned())
    }
    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        self.check_forced_error("consume_pairing")?;
        let mut pairings = self.pairings.lock().unwrap();
        if let Some(p) = pairings
            .iter_mut()
            .find(|p| p.pairing_id == pairing_id && p.client_id.is_none())
        {
            p.client_id = Some(client_id.to_owned());
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn count_unconsumed_pairings(&self, _now: &str) -> anyhow::Result<i64> {
        self.check_forced_error("count_unconsumed_pairings")?;
        if let Some(count) = self.forced_unconsumed_count {
            return Ok(count);
        }
        let pairings = self.pairings.lock().unwrap();
        Ok(pairings.iter().filter(|p| p.client_id.is_none()).count() as i64)
    }
    async fn delete_expired_pairings(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
    }
    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        self.check_forced_error("create_client_pairing")?;
        self.client_pairings_data
            .lock()
            .unwrap()
            .push(ClientPairingRow {
                client_id: client_id.to_owned(),
                pairing_id: pairing_id.to_owned(),
                client_jwt_issued_at: client_jwt_issued_at.to_owned(),
            });
        Ok(())
    }
    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let mut cp = self.client_pairings_data.lock().unwrap();
        let before = cp.len();
        cp.retain(|p| !(p.client_id == client_id && p.pairing_id == pairing_id));
        Ok(cp.len() < before)
    }
    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        self.check_forced_error("delete_client_pairing_and_cleanup")?;
        let mut cp = self.client_pairings_data.lock().unwrap();
        let before = cp.len();
        cp.retain(|p| !(p.client_id == client_id && p.pairing_id == pairing_id));
        let pairing_deleted = cp.len() < before;
        let mut client_deleted = false;
        if pairing_deleted && !cp.iter().any(|p| p.client_id == client_id) {
            drop(cp);
            self.clients
                .lock()
                .unwrap()
                .retain(|c| c.client_id != client_id);
            client_deleted = true;
        }
        Ok((pairing_deleted, client_deleted))
    }
    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        self.check_forced_error("update_client_jwt_issued_at")?;
        if self.force_update_false {
            return Ok(false);
        }
        let mut cp = self.client_pairings_data.lock().unwrap();
        if let Some(p) = cp
            .iter_mut()
            .find(|p| p.client_id == client_id && p.pairing_id == pairing_id)
        {
            p.client_jwt_issued_at = issued_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET: &str = "test-secret-key!";

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

fn make_client_row(client_id: &str, gpg_keys: &str) -> ClientRow {
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: "[]".to_owned(),
        default_kid: "".to_owned(),
        gpg_keys: gpg_keys.to_owned(),
    }
}

fn make_state(repo: PairingMockRepo) -> AppState {
    use crate::http::pairing::notifier::PairingNotifier;
    use crate::http::rate_limit::{SseConnectionTracker, config::SseConnectionConfig};

    AppState {
        repository: Arc::new(repo),
        base_url: "https://api.example.com".to_owned(),
        signing_key_secret: TEST_SECRET.to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
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
        .route("/pairing-token", get(get_pairing_token))
        .route("/pairing", post(pair_device))
        .route("/pairing", delete(delete_pairing_by_daemon))
        .route("/pairing/{pairing_id}", delete(delete_pairing_by_phone))
        .route("/pairing/refresh", post(refresh_client_jwt))
        .route("/pairing/gpg-keys", post(query_gpg_keys))
        .with_state(state)
}

fn json_body(tokens: &[String]) -> Body {
    let body = json!({ "client_jwts": tokens });
    Body::from(serde_json::to_vec(&body).unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_gpg_keys_returns_aggregated_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let gpg_keys_1 = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xABCD1234",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);
    let gpg_keys_2 = json!([{
        "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "key_id": "0xEF567890",
        "public_key": { "kty": "EC", "crv": "P-384" }
    }]);

    let client1 = make_client_row("fid-1", &gpg_keys_1.to_string());
    let client2 = make_client_row("fid-2", &gpg_keys_2.to_string());

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

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().extend(vec![client1, client2]);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-2", "pair-2");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[t1, t2]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let keys = json["gpg_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["client_id"], "fid-1");
    assert_eq!(keys[1]["client_id"], "fid-2");
}

#[tokio::test]
async fn query_gpg_keys_returns_empty_when_no_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let client = make_client_row("fid-1", "[]");
    let pairing = ClientPairingRow {
        client_id: "fid-1".into(),
        pairing_id: "pair-1".into(),
        client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
    };

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data.lock().unwrap().push(pairing);
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["gpg_keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn query_gpg_keys_missing_client_returns_remaining_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let gpg_keys_1 = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xABCD1234",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);

    // Only client1 exists in the DB; client2 (fid-deleted) is missing
    let client1 = make_client_row("fid-1", &gpg_keys_1.to_string());

    let pairings = vec![
        ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
        ClientPairingRow {
            client_id: "fid-deleted".into(),
            pairing_id: "pair-deleted".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
    ];

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client1);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-deleted", "pair-deleted");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[t1, t2]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let keys = json["gpg_keys"].as_array().unwrap();
    // Only keys from existing client fid-1; deleted client contributes nothing
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["client_id"], "fid-1");
}

#[tokio::test]
async fn query_gpg_keys_malformed_json_returns_500() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    // Client with invalid gpg_keys JSON stored in DB
    let client = make_client_row("fid-bad", "not-valid-json");

    let pairings = vec![ClientPairingRow {
        client_id: "fid-bad".into(),
        pairing_id: "pair-bad".into(),
        client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
    }];

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-bad", "pair-bad");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// Endpoint test helpers
// ===========================================================================

fn make_device_assertion_token(
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    sub: &str,
    path: &str,
) -> String {
    let claims = DeviceAssertionClaims {
        iss: sub.to_owned(),
        sub: sub.to_owned(),
        aud: format!("https://api.example.com{path}"),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

fn make_client_with_public_key(
    client_id: &str,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
) -> ClientRow {
    let pub_json = jwk_to_json(pub_jwk).unwrap();
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: kid.to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}

fn make_pairing_token(priv_jwk: &josekit::jwk::Jwk, kid: &str, pairing_id: &str) -> String {
    let claims = PairingClaims {
        sub: pairing_id.to_owned(),
        payload_type: PayloadType::Pairing,
        exp: 1_900_000_000,
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

// ===========================================================================
// GET /pairing-token
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_returns_200_with_token() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["pairing_token"].as_str().is_some());
    assert_eq!(json["expires_in"], 300);
}

#[tokio::test]
async fn get_pairing_token_returns_429_when_limit_reached() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let mut repo = PairingMockRepo::new(sk);
    repo.forced_unconsumed_count = Some(100); // matches unconsumed_pairing_limit
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===========================================================================
// POST /pairing
// ===========================================================================

#[tokio::test]
async fn pair_device_returns_200_with_pairing_id() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-test-1";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["pairing_id"], pairing_id);
    assert_eq!(json["ok"], true);
    assert_eq!(json["client_id"], "fid-1");
}

#[tokio::test]
async fn pair_device_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-expired";
    let past_expired = "2020-01-01T00:00:00+00:00";

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: past_expired.to_owned(),
        client_id: None,
    });

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn pair_device_already_consumed_returns_409() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consumed";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: Some("other-client".to_owned()), // already consumed
    });

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ===========================================================================
// DELETE /pairing/{pairing_id}  (by phone)
// ===========================================================================

#[tokio::test]
async fn delete_by_phone_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-del")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_by_phone_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No client_pairings → not found

    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/nonexistent");

    let response = app
        .oneshot(
            Request::delete("/pairing/nonexistent")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// DELETE /pairing  (by daemon)
// ===========================================================================

#[tokio::test]
async fn delete_by_daemon_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-daemon-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-daemon-del",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ===========================================================================
// POST /pairing/refresh
// ===========================================================================

#[tokio::test]
async fn refresh_returns_200_with_new_jwt() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["client_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    // No client_pairings → not found after JWT verification

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// Additional coverage tests
// ===========================================================================

// -- GET /pairing-token: no active signing key --------------------------------

#[tokio::test]
async fn get_pairing_token_no_signing_key_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let mut repo = PairingMockRepo::new(sk);
    repo.signing_key = None; // no active key
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid pairing_token format ------------------------------

#[tokio::test]
async fn pair_device_invalid_token_format_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);

    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": "not-a-valid-jwt" });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: unknown signing key in pairing_token ----------------------

#[tokio::test]
async fn pair_device_unknown_signing_key_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    // Generate a DIFFERENT key pair to sign the pairing token
    let (priv_other, _pub_other, other_kid) = generate_signing_key_pair().unwrap();

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);

    let state = make_state(repo);
    let app = build_app(state);

    // Sign the pairing token with the OTHER key (kid won't match repo)
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: pairing not found in DB -----------------------------------

#[tokio::test]
async fn pair_device_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No pairing record in DB — pairing_id from JWT won't be found

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

// -- DELETE /pairing (daemon): invalid JWT format -----------------------------

#[tokio::test]
async fn delete_by_daemon_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "not-a-valid-jwt" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing (daemon): pairing not found ------------------------------

#[tokio::test]
async fn delete_by_daemon_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    // No client_pairings → not found

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- DELETE /pairing (daemon): last pairing triggers client cleanup -----------

#[tokio::test]
async fn delete_by_daemon_last_pairing_deletes_client() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-only".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-only");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing/{pairing_id} (phone): last pairing triggers client cleanup

#[tokio::test]
async fn delete_by_phone_last_pairing_deletes_client() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-only".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-only");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-only")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing (daemon): multiple pairings, only one removed ------------

#[tokio::test]
async fn delete_by_daemon_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-a");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}

// -- POST /pairing/refresh: invalid JWT format --------------------------------

#[tokio::test]
async fn refresh_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "garbage-token" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing/{pairing_id} (phone): multiple pairings, keep client -----

#[tokio::test]
async fn delete_by_phone_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-a");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-a")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}

// ===========================================================================
// helpers.rs – direct unit tests for error paths
// ===========================================================================

// -- build_client_jwt_token: decrypt_private_key fails -------------------------

#[tokio::test]
async fn build_client_jwt_decrypt_error_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "not-valid-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = PairingMockRepo::new(bad_sk.clone());
    let state = make_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: private JWK parse fails ---------------------------

#[tokio::test]
async fn build_client_jwt_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    // Encrypt a valid JSON that is NOT a JWK
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = PairingMockRepo::new(bad_sk.clone());
    let state = make_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: public JWK parse fails ----------------------------

#[tokio::test]
async fn build_client_jwt_invalid_public_key_returns_500() {
    let (priv_jwk, _, kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_jwk).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: "not-valid-json".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = PairingMockRepo::new(bad_sk.clone());
    let state = make_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- verify_pairing_ownership: DB error in get_client_pairings -----------------

#[tokio::test]
async fn verify_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("get_client_pairings");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    let state = make_state(repo);

    let result = verify_pairing_ownership(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- remove_pairing_and_cleanup: DB error --------------------------------------

#[tokio::test]
async fn remove_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("delete_client_pairing_and_cleanup");
    let state = make_state(repo);

    let result = remove_pairing_and_cleanup(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- verify_pairing_ownership DB error through DELETE /pairing endpoint --------

#[tokio::test]
async fn delete_by_daemon_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("get_client_pairings");
    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- remove_pairing_and_cleanup DB error through DELETE /pairing endpoint ------

#[tokio::test]
async fn delete_by_daemon_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("delete_client_pairing_and_cleanup");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// pair.rs – additional error path tests
// ===========================================================================

// -- POST /pairing: malformed body (missing field) ----------------------------

#[tokio::test]
async fn pair_device_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    // Body with wrong field name
    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: invalid public JWK in signing key row ---------------------

#[tokio::test]
async fn pair_device_corrupt_public_key_returns_500() {
    let (priv_server, _, server_kid) = generate_signing_key_pair().unwrap();
    // Create a signing key row with valid private key but invalid public_key
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: "not-a-valid-jwk".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(bad_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_state(repo);
    let app = build_app(state);

    // Sign pairing token with the REAL private key but repo returns bad public_key
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid expired timestamp in pairing record ---------------

#[tokio::test]
async fn pair_device_invalid_expired_format_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-bad-ts";
    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: "not-a-valid-timestamp".to_owned(),
        client_id: None,
    });

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: consume_pairing DB error ----------------------------------

#[tokio::test]
async fn pair_device_consume_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consume-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("consume_pairing");

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: create_client_pairing DB error ----------------------------

#[tokio::test]
async fn pair_device_create_link_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-link-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("create_client_pairing");

    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: expired signing key returns 401 ---------------------------

#[tokio::test]
async fn pair_device_expired_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let expired_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_server).unwrap(),
        created_at: "2020-01-01T00:00:00Z".into(),
        expires_at: "2020-06-01T00:00:00Z".into(), // already expired
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(expired_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- POST /pairing: get_signing_key_by_kid DB error ---------------------------

#[tokio::test]
async fn pair_device_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_signing_key_by_kid");
    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: get_pairing_by_id DB error --------------------------------

#[tokio::test]
async fn pair_device_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_pairing_by_id");
    let state = make_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// refresh.rs – additional error path tests
// ===========================================================================

// -- POST /pairing/refresh: malformed body ------------------------------------

#[tokio::test]
async fn refresh_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing/refresh: signing key disappears between verify and fetch ---

#[tokio::test]
async fn refresh_signing_key_disappears_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = PairingMockRepo::new(sk);
    // First call to get_signing_key_by_kid succeeds (verify_one_token), second returns None
    repo.signing_key_by_kid_max_success = Some(1);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at returns false ---------

#[tokio::test]
async fn refresh_update_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = PairingMockRepo::new(sk);
    repo.force_update_false = true;
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at DB error --------------

#[tokio::test]
async fn refresh_update_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.force_error("update_client_jwt_issued_at");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: get_client_pairings DB error ----------------------

#[tokio::test]
async fn refresh_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = PairingMockRepo::new(sk);
    repo.force_error("get_client_pairings");

    let state = make_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// token.rs – additional error path tests
// ===========================================================================

// -- GET /pairing-token: count_unconsumed_pairings DB error -------------------

#[tokio::test]
async fn get_pairing_token_count_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("count_unconsumed_pairings");
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: create_pairing DB error ------------------------------

#[tokio::test]
async fn get_pairing_token_create_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    repo.force_error("create_pairing");
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: bad encrypted private key ----------------------------

#[tokio::test]
async fn get_pairing_token_bad_private_key_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "bad-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = PairingMockRepo::new(bad_sk);
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: invalid private JWK (decrypts to non-JWK) ------------

#[tokio::test]
async fn get_pairing_token_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = PairingMockRepo::new(bad_sk);
    let state = make_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing: malformed body ------------------------------------------

#[tokio::test]
async fn delete_by_daemon_malformed_body_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- DELETE /pairing/{pairing_id}: verify_pairing_ownership DB error ----------

#[tokio::test]
async fn delete_by_phone_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_client_pairings");
    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-1");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-1")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing/{pairing_id}: remove_pairing_and_cleanup DB error --------

#[tokio::test]
async fn delete_by_phone_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = PairingMockRepo::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    repo.force_error("delete_client_pairing_and_cleanup");
    let state = make_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-del")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// GET /pairing-session  (SSE)
// ===========================================================================

use super::get_pairing_session;

fn build_sse_app(state: AppState) -> Router {
    Router::new()
        .route("/pairing-session", get(get_pairing_session))
        .with_state(state)
}

#[tokio::test]
async fn session_missing_auth_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_invalid_bearer_scheme_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Basic abc123")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Bearer not-a-valid-jwt")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_unknown_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    // Generate a different key pair to sign the token
    let (priv_other, _pub_other, other_kid) = generate_signing_key_pair().unwrap();
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-1");

    let repo = PairingMockRepo::new(sk);
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");

    let repo = PairingMockRepo::new(sk);
    // No pairings in repo — get_pairing_by_id returns None
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-expired");

    let repo = PairingMockRepo::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-expired".to_owned(),
        expired: "2020-01-01T00:00:00+00:00".to_owned(), // past date
        client_id: None,
    });
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_already_paired_returns_sse_with_paired_event() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-done");

    let repo = PairingMockRepo::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-done".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: Some("fid-1".to_owned()),
    });
    // Need a client that exists for the client_jwt build
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-1".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.contains("event: paired"),
        "expected paired event in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_jwt\""),
        "expected client_jwt in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_id\""),
        "expected client_id in body: {body_str}"
    );
}

#[tokio::test]
async fn session_pending_pairing_returns_200_sse_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-pending");

    let repo = PairingMockRepo::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-pending".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // SSE stream starts with 200
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/event-stream"),
        "expected text/event-stream but got: {content_type}"
    );
}

#[tokio::test]
async fn session_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = PairingMockRepo::new(sk);
    repo.force_error("get_signing_key_by_kid");
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = PairingMockRepo::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-1".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    repo.force_error("get_pairing_by_id");
    let state = make_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_notify_delivers_paired_event_on_waiting_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-wait");

    let repo = PairingMockRepo::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-wait".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-w".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_state(repo);
    let notifier = state.pairing_notifier.clone();

    let app = build_sse_app(state);
    let request = Request::get("/pairing-session")
        .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
        .header("X-Forwarded-For", "10.0.0.1")
        .body(Body::empty())
        .unwrap();

    // Send SSE request — spawns the stream.
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Send the paired notification.
    use super::notifier::PairedEventData;
    notifier.notify(
        "pair-wait",
        PairedEventData {
            client_jwt: "jwt-val".to_owned(),
            client_id: "fid-w".to_owned(),
        },
    );

    let body_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("timed out reading SSE body")
    .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        body_str.contains("event: paired"),
        "expected paired event: {body_str}"
    );
}
