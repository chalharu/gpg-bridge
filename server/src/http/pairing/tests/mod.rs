use axum::Router;
use axum::body::Body;
use axum::routing::{delete, get, post};
use serde_json::json;

use crate::http::AppState;
use crate::jwt::{DeviceAssertionClaims, PairingClaims, PayloadType, jwk_to_json, sign_jws};
use crate::repository::ClientRow;

use super::{
    delete_pairing_by_daemon, delete_pairing_by_phone, get_pairing_token, pair_device,
    query_gpg_keys, refresh_client_jwt,
};

mod coverage;
mod crud;
mod gpg_keys;
mod helpers_unit;
mod pair_errors;
mod refresh_token_errors;
mod sse;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
