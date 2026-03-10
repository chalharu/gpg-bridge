use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, header};
use axum::routing::{delete, get, patch, post};
use serde_json::json;

use crate::http::AppState;
use crate::jwt::{
    DeviceAssertionClaims, build_signing_key_row, generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{ClientRepository, ClientRow, SigningKeyRepository, SigningKeyRow};
use crate::test_support::{
    build_test_sqlite_repo, make_test_app_state_arc, make_test_client_row_with_issued_at,
};

use super::{
    add_gpg_key, add_public_key, delete_device, delete_gpg_key, delete_public_key, list_gpg_keys,
    list_public_keys, refresh_device_jwt, register_device, update_device,
};

mod gpg_key;
mod public_key;
mod register;
mod register_mutations;

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

fn make_client_row(
    client_id: &str,
    device_token: &str,
    public_keys: &str,
    default_kid: &str,
) -> ClientRow {
    make_test_client_row_with_issued_at(
        client_id,
        device_token,
        public_keys.to_owned(),
        default_kid,
        "[]",
        chrono::Utc::now().to_rfc3339(),
    )
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

struct DeviceAppFixture {
    repo: Arc<crate::repository::SqliteRepository>,
    app: Router,
}

impl DeviceAppFixture {
    async fn new() -> Self {
        let (sk, _) = make_signing_key_row();
        let (repo, app) = build_sqlite_device_app(&sk).await;

        Self { repo, app }
    }

    async fn with_client(client: &ClientRow) -> Self {
        let fixture = Self::new().await;
        fixture.repo.create_client(client).await.unwrap();
        fixture
    }
}

async fn build_sqlite_device_app(
    signing_key: &SigningKeyRow,
) -> (Arc<crate::repository::SqliteRepository>, Router) {
    let repo = build_test_sqlite_repo().await;
    repo.store_signing_key(signing_key).await.unwrap();

    let app = build_test_router(make_test_app_state_arc(
        Arc::clone(&repo) as Arc<dyn crate::repository::SignatureRepository>
    ));

    (repo, app)
}

async fn build_sqlite_device_app_with_client(
    signing_key: &SigningKeyRow,
    client: &ClientRow,
) -> (Arc<crate::repository::SqliteRepository>, Router) {
    let (repo, app) = build_sqlite_device_app(signing_key).await;
    repo.create_client(client).await.unwrap();
    (repo, app)
}

fn json_request(method: Method, uri: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn authed_request(method: Method, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn authed_json_request(
    method: Method,
    uri: &str,
    token: &str,
    body: &serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn post_device_json_request(
    uri: &str,
    token: &str,
    body: &serde_json::Value,
) -> Request<Body> {
    authed_json_request(Method::POST, uri, token, body)
}

fn get_device_request(uri: &str, token: &str) -> Request<Body> {
    authed_request(Method::GET, uri, token)
}

fn delete_device_item_request(resource: &str, item: &str, token: &str) -> Request<Body> {
    authed_request(Method::DELETE, &format!("{resource}/{item}"), token)
}

// ---------------------------------------------------------------------------
// POST /device tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// GPG key test helpers
// ---------------------------------------------------------------------------

fn make_gpg_client_row(
    client_id: &str,
    public_keys: &str,
    default_kid: &str,
    gpg_keys: &str,
) -> ClientRow {
    make_test_client_row_with_issued_at(
        client_id,
        "tok",
        public_keys.to_owned(),
        default_kid,
        gpg_keys.to_owned(),
        chrono::Utc::now().to_rfc3339(),
    )
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
