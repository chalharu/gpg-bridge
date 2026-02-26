use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::{delete, patch, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::fcm::NoopFcmValidator;
use crate::jwt::{
    DeviceAssertionClaims, DeviceClaims, PayloadType, build_signing_key_row,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{
    ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
};

use super::{delete_device, refresh_device_jwt, register_device, update_device};

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DeviceMockRepo {
    clients: Mutex<Vec<ClientRow>>,
    signing_key: Option<SigningKeyRow>,
    jti_accepted: bool,
}

impl DeviceMockRepo {
    fn new(signing_key: SigningKeyRow) -> Self {
        Self {
            clients: Mutex::new(Vec::new()),
            signing_key: Some(signing_key),
            jti_accepted: true,
        }
    }

    fn with_client(signing_key: SigningKeyRow, client: ClientRow) -> Self {
        Self {
            clients: Mutex::new(vec![client]),
            signing_key: Some(signing_key),
            jti_accepted: true,
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
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(self.jti_accepted)
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
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
    AppState {
        repository: Arc::new(repo),
        base_url: BASE_URL.to_owned(),
        signing_key_secret: SECRET.to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        fcm_validator: Arc::new(NoopFcmValidator),
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
