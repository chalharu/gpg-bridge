use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::{delete, get, patch, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::fcm::{NoopFcmSender, NoopFcmValidator};
use crate::jwt::{
    DeviceAssertionClaims, DeviceClaims, PayloadType, build_signing_key_row,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{
    ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
};

use super::{
    add_gpg_key, add_public_key, delete_device, delete_gpg_key, delete_public_key, list_gpg_keys,
    list_public_keys, refresh_device_jwt, register_device, update_device,
};

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DeviceMockRepo {
    clients: Mutex<Vec<ClientRow>>,
    signing_key: Option<SigningKeyRow>,
    jti_accepted: bool,
    in_flight_kids: Mutex<Vec<String>>,
    force_gpg_update_conflict: bool,
}

impl DeviceMockRepo {
    fn new(signing_key: SigningKeyRow) -> Self {
        Self {
            clients: Mutex::new(Vec::new()),
            signing_key: Some(signing_key),
            jti_accepted: true,
            in_flight_kids: Mutex::new(Vec::new()),
            force_gpg_update_conflict: false,
        }
    }

    fn with_client(signing_key: SigningKeyRow, client: ClientRow) -> Self {
        Self {
            clients: Mutex::new(vec![client]),
            signing_key: Some(signing_key),
            jti_accepted: true,
            in_flight_kids: Mutex::new(Vec::new()),
            force_gpg_update_conflict: false,
        }
    }
}

#[async_trait]
impl SignatureRepository for DeviceMockRepo {
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
    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        self.clients.lock().unwrap().push(row.clone());
        Ok(())
    }
    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.client_id == client_id))
    }
    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.device_token == device_token)
            .cloned())
    }
    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.device_token = device_token.to_owned();
        }
        Ok(())
    }
    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.default_kid = default_kid.to_owned();
        }
        Ok(())
    }
    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        self.clients
            .lock()
            .unwrap()
            .retain(|c| c.client_id != client_id);
        Ok(())
    }
    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.device_jwt_issued_at = issued_at.to_owned();
        }
        Ok(())
    }
    async fn get_client_pairings(&self, _: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        Ok(vec![])
    }
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(None)
    }
    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients
            .iter_mut()
            .find(|c| c.client_id == client_id && c.updated_at == expected_updated_at)
        {
            c.public_keys = public_keys.to_owned();
            c.default_kid = default_kid.to_owned();
            c.updated_at = updated_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool> {
        Ok(self.in_flight_kids.lock().unwrap().iter().any(|k| k == kid))
    }
    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        if self.force_gpg_update_conflict {
            return Ok(false);
        }
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients
            .iter_mut()
            .find(|c| c.client_id == client_id && c.updated_at == expected_updated_at)
        {
            c.gpg_keys = gpg_keys.to_owned();
            c.updated_at = updated_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(self.jti_accepted)
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
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
    async fn update_client_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_request(&self, _: &crate::repository::CreateRequestRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn count_pending_requests_for_pairing(&self, _: &str, _: &str) -> anyhow::Result<i64> {
        unimplemented!()
    }
    async fn create_audit_log(&self, _: &crate::repository::AuditLogRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_expired_audit_logs(&self, _: &str, _: &str, _: &str) -> anyhow::Result<u64> {
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
    async fn get_pending_requests_for_client(
        &self,
        _: &str,
    ) -> anyhow::Result<Vec<crate::repository::FullRequestRow>> {
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const SECRET: &str = "test-secret-key!";
const BASE_URL: &str = "https://api.example.com";
const X_COORD: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const Y_COORD: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn make_signing_key_row() -> (SigningKeyRow, josekit::jwk::Jwk) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let row = build_signing_key_row(&priv_jwk, &pub_jwk, &kid, SECRET, 90).unwrap();
    (row, pub_jwk)
}

fn make_state(repo: impl SignatureRepository + 'static) -> AppState {
    make_state_with_arc_repo(Arc::new(repo))
}

fn make_state_with_repo(repo: Arc<DeviceMockRepo>) -> AppState {
    make_state_with_arc_repo(repo)
}

fn make_state_with_arc_repo(repository: Arc<dyn SignatureRepository>) -> AppState {
    use crate::http::pairing::notifier::PairingNotifier;
    use crate::http::rate_limit::{SseConnectionTracker, config::SseConnectionConfig};

    AppState {
        repository,
        base_url: BASE_URL.to_owned(),
        signing_key_secret: SECRET.to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_validator: Arc::new(NoopFcmValidator),
        fcm_sender: Arc::new(NoopFcmSender),
        sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: crate::http::signing::notifier::SignEventNotifier::new(),
    }
}

fn make_client_row(
    client_id: &str,
    device_token: &str,
    public_keys: &str,
    default_kid: &str,
) -> ClientRow {
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: device_token.to_owned(),
        device_jwt_issued_at: chrono::Utc::now().to_rfc3339(),
        public_keys: public_keys.to_owned(),
        default_kid: default_kid.to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}

fn register_body(fid: &str, token: &str) -> serde_json::Value {
    json!({
        "device_token": token,
        "firebase_installation_id": fid,
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256", "x": X_COORD, "y": Y_COORD }],
                "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }]
            }
        }
    })
}

/// Build a DeviceAssertion JWT for authenticated endpoints.
fn make_device_assertion(priv_jwk: &josekit::jwk::Jwk, kid: &str, sub: &str, path: &str) -> String {
    let claims = DeviceAssertionClaims {
        iss: sub.to_owned(),
        sub: sub.to_owned(),
        aud: format!("{BASE_URL}{path}"),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

fn build_test_router(state: AppState) -> Router {
    Router::new()
        .route("/device", post(register_device))
        .route("/device", patch(update_device))
        .route("/device", delete(delete_device))
        .route("/device/refresh", post(refresh_device_jwt))
        .route("/device/public_key", post(add_public_key))
        .route("/device/public_key", get(list_public_keys))
        .route("/device/public_key/{kid}", delete(delete_public_key))
        .route("/device/gpg_key", post(add_gpg_key))
        .route("/device/gpg_key", get(list_gpg_keys))
        .route("/device/gpg_key/{keygrip}", delete(delete_gpg_key))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// POST /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_device_success() {
    let (sk, _) = make_signing_key_row();
    let state = make_state(DeviceMockRepo::new(sk));
    let app = build_test_router(state);

    let body = register_body("fid-1", "token-1");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["device_jwt"].as_str().is_some());
}

#[tokio::test]
async fn register_device_fid_conflict() {
    let (sk, _) = make_signing_key_row();
    let client = make_client_row("fid-1", "old-token", "[]", "kid-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let body = register_body("fid-1", "token-1");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_token_conflict() {
    let (sk, _) = make_signing_key_row();
    let client = make_client_row("other-fid", "shared-token", "[]", "kid-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let body = register_body("fid-1", "shared-token");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_missing_sig_keys() {
    let (sk, _) = make_signing_key_row();
    let state = make_state(DeviceMockRepo::new(sk));
    let app = build_test_router(state);

    let body = json!({
        "device_token": "t",
        "firebase_installation_id": "fid-1",
        "public_key": { "keys": { "sig": [], "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }] } }
    });
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_device_invalid_sig_key_alg() {
    let (sk, _) = make_signing_key_row();
    let state = make_state(DeviceMockRepo::new(sk));
    let app = build_test_router(state);

    let body = json!({
        "device_token": "t",
        "firebase_installation_id": "fid-1",
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "RS256", "x": X_COORD, "y": Y_COORD }],
                "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }]
            }
        }
    });
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// PATCH /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_device_token_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "old-token", &keys, "enc-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-token" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "tok", &keys, "enc-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": "enc-1" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_not_found_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "tok", &keys, "enc-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": "nonexistent-kid" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_device_both_fields_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "old-tok", &keys, "enc-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-tok", "default_kid": "enc-1" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_empty_body_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let client = make_client_row("fid-2", "tok", &format!("[{pub_json}]"), &kid);
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-2", "/device");
    let body = json!({});
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// DELETE /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_device_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let client = make_client_row("fid-3", "tok", &format!("[{pub_json}]"), &kid);
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-3", "/device");
    let response = app
        .oneshot(
            Request::delete("/device")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// POST /device/refresh tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_device_jwt_success() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _server_pub) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let keys = format!("[{client_pub_json}]");
    let client = make_client_row("fid-4", "tok", &keys, &client_kid);
    let repo = DeviceMockRepo::with_client(sk.clone(), client);
    let state = make_state(repo);

    // Issue a device_jwt using the server signing key.
    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "fid-4".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_device_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-4", "/device/refresh");
    let body = json!({ "device_jwt": old_device_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["device_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_device_jwt_sub_mismatch_returns_401() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let client = make_client_row("fid-5", "tok", &format!("[{client_pub_json}]"), &client_kid);
    let repo = DeviceMockRepo::with_client(sk.clone(), client);
    let state = make_state(repo);

    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "wrong-fid".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-5", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_device_jwt_expired_issued_at_returns_401() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let mut client = make_client_row("fid-6", "tok", &format!("[{client_pub_json}]"), &client_kid);
    // Set device_jwt_issued_at far in the past so validity check fails.
    client.device_jwt_issued_at = "2020-01-01T00:00:00+00:00".to_owned();
    let repo = DeviceMockRepo::with_client(sk.clone(), client);
    let state = make_state(repo);

    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "fid-6".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-6", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Helper: build a client with both sig and enc keys for public_key tests
// ---------------------------------------------------------------------------

fn make_pk_test_setup() -> (
    josekit::jwk::Jwk,
    String,
    SigningKeyRow,
    ClientRow,
    String,
    String,
) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let enc_kid = "enc-1";
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"{enc_kid}\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-pk", "tok-pk", &keys, enc_kid);
    (priv_jwk, kid, sk, client, enc_kid.to_owned(), keys)
}

// ---------------------------------------------------------------------------
// POST /device/public_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_public_key_sig_success() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_enc_success() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_with_default_kid_change() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": "enc-new"
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_invalid_key_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "RS256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_empty_keys_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({ "keys": [] });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_unsupported_use_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "other", "crv": "P-256", "alg": "ES256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// GET /device/public_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_public_keys_returns_all() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let response = app
        .oneshot(
            Request::get("/device/public_key")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["keys"].as_array().unwrap().len(), 2);
    assert_eq!(json["default_kid"].as_str().unwrap(), enc_kid);
}

// ---------------------------------------------------------------------------
// DELETE /device/public_key/{kid} tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_public_key_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // Patch pub_json to include "use":"sig" and "alg":"ES256" (generate_signing_key_pair omits them)
    let mut pub_val: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
    pub_val["use"] = json!("sig");
    pub_val["alg"] = json!("ES256");
    let pub_json_patched = serde_json::to_string(&pub_val).unwrap();
    // Two sig keys + one enc key
    let keys = format!(
        "[{pub_json_patched},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-2\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-del", "tok-del", &keys, "enc-1");
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-del", "/device/public_key/sig-2");
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-2")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_public_key_last_sig_returns_409() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{kid}"),
    );
    let response = app
        .oneshot(
            Request::delete(format!("/device/public_key/{kid}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_last_enc_returns_409() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{enc_kid}"),
    );
    let response = app
        .oneshot(
            Request::delete(format!("/device/public_key/{enc_kid}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_not_found_returns_404() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key/nonexistent");
    let response = app
        .oneshot(
            Request::delete("/device/public_key/nonexistent")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_public_key_in_flight_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // Two sig keys + one enc key
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-flight\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-flight", "tok-flight", &keys, "enc-1");
    let mut repo = DeviceMockRepo::with_client(sk, client);
    repo.in_flight_kids = Mutex::new(vec!["sig-flight".to_owned()]);
    let state = make_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-flight",
        "/device/public_key/sig-flight",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-flight")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_auto_reassign_default_kid() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // One sig key + two enc keys, default_kid = enc-del
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-del\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-keep\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-reassign", "tok-reassign", &keys, "enc-del");
    let repo = Arc::new(DeviceMockRepo::with_client(sk, client));
    let state = make_state_with_repo(repo.clone());
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-reassign",
        "/device/public_key/enc-del",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/enc-del")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // FINDING-10: verify default_kid was reassigned to the remaining enc key
    let clients = repo.clients.lock().unwrap();
    let c = clients
        .iter()
        .find(|c| c.client_id == "fid-reassign")
        .unwrap();
    assert_eq!(c.default_kid, "enc-keep");
}

// ---------------------------------------------------------------------------
// Edge-case tests (FINDING-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_public_key_default_kid_referencing_sig_key_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    // default_kid points to the sig key (kid), which is not an enc key
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": kid
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_default_kid_nonexistent_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": "nonexistent-kid"
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_public_key_no_default_kid_reassign_when_not_affected() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let mut pub_val: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
    pub_val["use"] = json!("sig");
    pub_val["alg"] = json!("ES256");
    let pub_json_patched = serde_json::to_string(&pub_val).unwrap();
    // Two sig keys + one enc key, default_kid = enc-1
    let keys = format!(
        "[{pub_json_patched},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-extra\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-noreassign", "tok-noreassign", &keys, "enc-1");
    let repo = Arc::new(DeviceMockRepo::with_client(sk, client));
    let state = make_state_with_repo(repo.clone());
    let app = build_test_router(state);

    // Delete a sig key that is NOT the default_kid
    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-noreassign",
        "/device/public_key/sig-extra",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-extra")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify default_kid is unchanged
    let clients = repo.clients.lock().unwrap();
    let c = clients
        .iter()
        .find(|c| c.client_id == "fid-noreassign")
        .unwrap();
    assert_eq!(c.default_kid, "enc-1");
}

#[tokio::test]
async fn add_public_key_duplicate_kid_rejected() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    // Try to add a key with the same kid as the existing enc key
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": enc_kid, "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// GPG key test helpers
// ---------------------------------------------------------------------------

fn make_gpg_client_row(
    client_id: &str,
    public_keys: &str,
    default_kid: &str,
    gpg_keys: &str,
) -> ClientRow {
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: chrono::Utc::now().to_rfc3339(),
        public_keys: public_keys.to_owned(),
        default_kid: default_kid.to_owned(),
        gpg_keys: gpg_keys.to_owned(),
    }
}

fn make_gpg_test_setup() -> (josekit::jwk::Jwk, String, SigningKeyRow, ClientRow) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_gpg_client_row("fid-gpg", &keys, "enc-1", "[]");
    (priv_jwk, kid, sk, client)
}

// ---------------------------------------------------------------------------
// POST /device/gpg_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_gpg_key_success() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD1234EF567890",
            "public_key": { "kty": "EC", "crv": "P-256", "x": "abc", "y": "def" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_gpg_key_empty_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({ "gpg_keys": [] });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_invalid_keygrip_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "TOOSHORT",
            "key_id": "0xABCD",
            "public_key": { "kty": "EC" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_invalid_key_id_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "not-hex!",
            "public_key": { "kty": "EC" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_empty_public_key_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD",
            "public_key": {}
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_upsert_overwrites_existing() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let existing_gpg = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xAABB",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);
    let client = make_gpg_client_row("fid-upsert", &keys, "enc-1", &existing_gpg.to_string());
    let repo = Arc::new(DeviceMockRepo::with_client(sk, client));
    let state = make_state_with_repo(repo.clone());
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-upsert", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xCCDD",
            "public_key": { "kty": "EC", "crv": "P-384" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let clients = repo.clients.lock().unwrap();
    let c = clients
        .iter()
        .find(|c| c.client_id == "fid-upsert")
        .unwrap();
    let gpg_keys: Vec<serde_json::Value> = serde_json::from_str(&c.gpg_keys).unwrap();
    assert_eq!(gpg_keys.len(), 1);
    assert_eq!(gpg_keys[0]["key_id"], "0xCCDD");
}

// ---------------------------------------------------------------------------
// GET /device/gpg_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_gpg_keys_returns_registered() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "key_id": "0xEF",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-list", &keys, "enc-1", &gpg.to_string());
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-list", "/device/gpg_key");
    let response = app
        .oneshot(
            Request::get("/device/gpg_key")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["gpg_keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn list_gpg_keys_empty() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let response = app
        .oneshot(
            Request::get("/device/gpg_key")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
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

// ---------------------------------------------------------------------------
// DELETE /device/gpg_key/{keygrip} tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_gpg_key_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-gpg", &keys, "enc-1", &gpg.to_string());
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-del-gpg",
        "/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_gpg_key_not_found() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-gpg",
        "/device/gpg_key/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn add_gpg_key_multiple_keys_success() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo = Arc::new(DeviceMockRepo::with_client(sk, client));
    let state = make_state_with_repo(repo.clone());
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [
            {
                "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id": "0xABCD1234",
                "public_key": { "kty": "EC", "crv": "P-256" }
            },
            {
                "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "key_id": "0xEF567890",
                "public_key": { "kty": "EC", "crv": "P-384" }
            }
        ]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let clients = repo.clients.lock().unwrap();
    let c = clients.iter().find(|c| c.client_id == "fid-gpg").unwrap();
    let gpg_keys: Vec<serde_json::Value> = serde_json::from_str(&c.gpg_keys).unwrap();
    assert_eq!(gpg_keys.len(), 2);
}

#[tokio::test]
async fn add_gpg_key_concurrent_modification_conflict() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let mut repo = DeviceMockRepo::with_client(sk, client);
    repo.force_gpg_update_conflict = true;
    let state = make_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD1234",
            "public_key": { "kty": "EC", "crv": "P-256" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn add_gpg_key_non_object_public_key_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD",
            "public_key": "not-an-object"
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_key_id_too_long_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    // "0x" + 41 hex chars = 43 chars total, exceeds maxLength:42
    let long_key_id = format!("0x{}", "A".repeat(41));
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": long_key_id,
            "public_key": { "kty": "EC" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_gpg_key_concurrent_modification_conflict() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-conflict", &keys, "enc-1", &gpg.to_string());
    let mut repo = DeviceMockRepo::with_client(sk, client);
    repo.force_gpg_update_conflict = true;
    let state = make_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-del-conflict",
        "/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_gpg_key_invalid_keygrip_format() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let state = make_state(DeviceMockRepo::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key/invalid-format");
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/invalid-format")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
