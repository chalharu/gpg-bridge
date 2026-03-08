use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use axum::routing::{delete, get, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DeviceAssertionClaims, PairingClaims, PayloadType, generate_signing_key_pair, jwk_to_json,
    sign_jws,
};
use crate::repository::{ClientPairingRow, ClientRow, PairingRow};
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
};

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

fn build_test_app(repo: MockRepository) -> Router {
    build_app(make_test_app_state(repo))
}

fn make_pairing_repo() -> (josekit::jwk::Jwk, josekit::jwk::Jwk, String, MockRepository) {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    (priv_server, pub_server, server_kid, MockRepository::new(sk))
}

fn add_client_with_assertion_key(
    repo: &MockRepository,
    client_id: &str,
) -> (josekit::jwk::Jwk, String) {
    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_with_public_key(
            client_id,
            &pub_client,
            &client_kid,
        ));
    (priv_client, client_kid)
}

fn add_pairing(repo: &MockRepository, pairing_id: &str, expired: &str, client_id: Option<&str>) {
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: expired.to_owned(),
        client_id: client_id.map(str::to_owned),
    });
}

fn add_unconsumed_pairing(repo: &MockRepository, pairing_id: &str) {
    add_pairing(repo, pairing_id, "2099-01-01T00:00:00+00:00", None);
}

fn add_client_pairing(repo: &MockRepository, client_id: &str, pairing_id: &str) {
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: client_id.into(),
            pairing_id: pairing_id.into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
}

fn get_pairing_token_request() -> Request<Body> {
    Request::get("/pairing-token").body(Body::empty()).unwrap()
}

fn pair_device_request(pairing_jwt: &str, device_assertion: &str) -> Request<Body> {
    let body_json = json!({ "pairing_jwt": pairing_jwt });
    Request::post("/pairing")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap()
}

fn pair_device_request_for(
    server_priv: &josekit::jwk::Jwk,
    server_kid: &str,
    pairing_id: &str,
    client_priv: &josekit::jwk::Jwk,
    client_kid: &str,
    client_id: &str,
) -> Request<Body> {
    let pairing_token = make_pairing_token(server_priv, server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(client_priv, client_kid, client_id, "/pairing");
    pair_device_request(&pairing_token, &device_assertion)
}

async fn pair_device_status_for(
    repo: MockRepository,
    server_priv: &josekit::jwk::Jwk,
    server_kid: &str,
    pairing_id: &str,
    client_priv: &josekit::jwk::Jwk,
    client_kid: &str,
    client_id: &str,
) -> StatusCode {
    response_status(
        build_test_app(repo),
        pair_device_request_for(
            server_priv,
            server_kid,
            pairing_id,
            client_priv,
            client_kid,
            client_id,
        ),
    )
    .await
}

#[allow(dead_code)]
fn pair_device_json_request(body_json: serde_json::Value, device_assertion: &str) -> Request<Body> {
    Request::post("/pairing")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap()
}

fn delete_pairing_by_phone_request(pairing_id: &str, device_assertion: &str) -> Request<Body> {
    Request::delete(format!("/pairing/{pairing_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
        .body(Body::empty())
        .unwrap()
}

fn delete_pairing_by_phone_request_for(
    pairing_id: &str,
    client_priv: &josekit::jwk::Jwk,
    client_kid: &str,
    client_id: &str,
) -> Request<Body> {
    let path = format!("/pairing/{pairing_id}");
    let device_assertion = make_device_assertion_token(client_priv, client_kid, client_id, &path);
    delete_pairing_by_phone_request(pairing_id, &device_assertion)
}

fn delete_pairing_by_daemon_request(client_jwt: &str) -> Request<Body> {
    let body_json = json!({ "client_jwt": client_jwt });
    Request::delete("/pairing")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap()
}

fn delete_pairing_by_daemon_request_for(
    server_priv: &josekit::jwk::Jwk,
    server_pub: &josekit::jwk::Jwk,
    server_kid: &str,
    client_id: &str,
    pairing_id: &str,
) -> Request<Body> {
    let client_jwt = make_client_jwt(server_priv, server_pub, server_kid, client_id, pairing_id);
    delete_pairing_by_daemon_request(&client_jwt)
}

#[allow(dead_code)]
fn refresh_pairing_request(client_jwt: &str) -> Request<Body> {
    let body_json = json!({ "client_jwt": client_jwt });
    Request::post("/pairing/refresh")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap()
}

fn refresh_pairing_request_for(
    server_priv: &josekit::jwk::Jwk,
    server_pub: &josekit::jwk::Jwk,
    server_kid: &str,
    client_id: &str,
    pairing_id: &str,
) -> Request<Body> {
    let client_jwt = make_client_jwt(server_priv, server_pub, server_kid, client_id, pairing_id);
    refresh_pairing_request(&client_jwt)
}

#[allow(dead_code)]
fn refresh_pairing_json_request(body_json: serde_json::Value) -> Request<Body> {
    Request::post("/pairing/refresh")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap()
}

#[allow(dead_code)]
fn pairing_session_request(auth_header: Option<&str>) -> Request<Body> {
    let mut builder = Request::get("/pairing-session").header("X-Forwarded-For", "10.0.0.1");
    if let Some(value) = auth_header {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(Body::empty()).unwrap()
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

async fn response_status(app: Router, request: Request<Body>) -> StatusCode {
    app.oneshot(request).await.unwrap().status()
}

async fn response_json(response: Response) -> serde_json::Value {
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}
