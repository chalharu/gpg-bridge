use axum::Router;
use axum::routing::{delete, get, patch, post};
use serde_json::json;

use crate::http::AppState;
use crate::jwt::{
    DeviceAssertionClaims, build_signing_key_row, generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{ClientRow, SigningKeyRow};

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
