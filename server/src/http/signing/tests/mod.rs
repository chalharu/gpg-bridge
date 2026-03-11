use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, PayloadType, RequestClaims, SignClaims, generate_signing_key_pair,
    jwk_to_json, sign_jws,
};
use crate::repository::{ClientPairingRow, ClientRow, FullRequestRow, RequestRow};
use crate::test_support::{
    MockRepository, make_device_assertion, make_signing_key_row, make_test_client_pairing_row,
    make_test_client_row,
};

use super::{get_sign_request, post_sign_request, post_sign_result};

mod delete_request;
mod get_and_result;
mod patch_request;
mod post_request;
mod sign_events;
mod unit_tests;

// ---------------------------------------------------------------------------

const VALID_COORD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn make_client_row_with_key(client_id: &str, kid: &str, key_use: &str, alg: &str) -> ClientRow {
    let key = json!({
        "kid": kid,
        "kty": "EC",
        "crv": "P-256",
        "x": VALID_COORD,
        "y": VALID_COORD,
        "use": key_use,
        "alg": alg
    });
    make_test_client_row(
        client_id,
        "tok",
        serde_json::to_string(&vec![key]).unwrap(),
        kid,
        "[]",
    )
}

fn make_client_row_with_enc_key(client_id: &str, enc_kid: &str) -> ClientRow {
    make_client_row_with_key(client_id, enc_kid, "enc", "ECDH-ES+A256KW")
}

fn make_client_row_no_enc_key(client_id: &str) -> ClientRow {
    make_client_row_with_key(client_id, "sig-kid", "sig", "ES256")
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", post(post_sign_request))
        .with_state(state)
}

fn build_get_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", get(get_sign_request))
        .with_state(state)
}

fn build_result_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-result", post(post_sign_result))
        .with_state(state)
}

fn make_signing_repo() -> (josekit::jwk::Jwk, josekit::jwk::Jwk, String, MockRepository) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    (priv_jwk, pub_jwk, kid, MockRepository::new(key_row))
}

fn make_daemon_auth_repo() -> (
    josekit::jwk::Jwk,
    String,
    josekit::jwk::Jwk,
    String,
    MockRepository,
    String,
) {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&server_priv, &server_pub, &server_kid);

    (
        server_priv,
        server_kid,
        daemon_priv,
        daemon_kid,
        MockRepository::new(key_row),
        jwk_to_json(&daemon_pub).unwrap(),
    )
}

fn make_daemon_auth_request_row(
    request_id: &str,
    status: &str,
    daemon_public_key: impl Into<String>,
) -> RequestRow {
    RequestRow {
        request_id: request_id.into(),
        status: status.into(),
        daemon_public_key: daemon_public_key.into(),
    }
}

fn make_daemon_auth_full_request_row(
    request_id: &str,
    status: &str,
    expired: &str,
    signature: Option<&str>,
    daemon_public_key: impl Into<String>,
) -> FullRequestRow {
    make_single_client_full_request_row(
        request_id,
        status,
        expired,
        signature,
        daemon_public_key,
        "{}",
    )
}

fn make_single_client_full_request_row(
    request_id: &str,
    status: &str,
    expired: &str,
    signature: Option<&str>,
    daemon_public_key: impl Into<String>,
    daemon_enc_public_key: impl Into<String>,
) -> FullRequestRow {
    FullRequestRow {
        request_id: request_id.into(),
        status: status.into(),
        expired: expired.into(),
        signature: signature.map(str::to_owned),
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: daemon_public_key.into(),
        daemon_enc_public_key: daemon_enc_public_key.into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    }
}

fn seed_single_client_request_links(
    full_request: &mut FullRequestRow,
    client_id: &str,
    pairing_id: &str,
    e2e_kid: &str,
) {
    full_request.pairing_ids = format!(r#"{{"{client_id}":"{pairing_id}"}}"#);
    full_request.e2e_kids = format!(r#"{{"{client_id}":"{e2e_kid}"}}"#);
}

fn seed_daemon_auth_request(
    repo: &MockRepository,
    request_id: &str,
    status: &str,
    daemon_public_key: &str,
    full_request: Option<FullRequestRow>,
) {
    *repo.request.lock().unwrap() = Some(make_daemon_auth_request_row(
        request_id,
        status,
        daemon_public_key,
    ));
    *repo.full_request.lock().unwrap() = full_request;
}

fn add_signing_client(repo: &MockRepository, client_id: &str) -> (josekit::jwk::Jwk, String) {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&client_pub).unwrap();
    repo.clients.lock().unwrap().push(make_test_client_row(
        client_id,
        "tok",
        format!("[{pub_json}]"),
        &client_kid,
        "[]",
    ));
    (client_priv, client_kid)
}

fn add_signing_client_pairing(repo: &MockRepository, client_id: &str, pairing_id: &str) {
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(make_test_client_pairing_row(client_id, pairing_id));
}

fn make_pending_request(
    request_id: &str,
    client_id: &str,
    pairing_id: &str,
    encrypted_payload: Option<&str>,
) -> FullRequestRow {
    FullRequestRow {
        request_id: request_id.into(),
        status: "pending".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: format!(r#"["{client_id}"]"#),
        daemon_public_key: "{}".into(),
        daemon_enc_public_key: r#"{"kty":"EC","crv":"P-256"}"#.into(),
        pairing_ids: format!(r#"{{"{client_id}":"{pairing_id}"}}"#),
        e2e_kids: "{}".into(),
        encrypted_payloads: encrypted_payload.map(|payload| {
            format!(r#"[{{"client_id":"{client_id}","encrypted_data":"{payload}"}}]"#)
        }),
        unavailable_client_ids: "[]".into(),
    }
}

fn make_full_request(request_id: &str, status: &str, signature: Option<&str>) -> FullRequestRow {
    make_single_client_full_request_row(
        request_id,
        status,
        "2027-01-01T00:00:00Z",
        signature,
        "{}",
        "{}",
    )
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

fn get_request_with_auth(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/sign-request")
        .method("GET")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn make_sign_jwt(
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    request_id: &str,
    client_id: &str,
) -> String {
    let exp = chrono::Utc::now().timestamp() + 300;
    let claims = SignClaims {
        sub: request_id.to_owned(),
        client_id: client_id.to_owned(),
        payload_type: PayloadType::Sign,
        exp,
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

fn post_result_json(token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .uri("/sign-result")
        .method("POST")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Setup common test fixtures: signing key pair, mock repo with a client + pairing.
fn setup_happy_path() -> (josekit::jwk::Jwk, josekit::jwk::Jwk, String, MockRepository) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(sk);

    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
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
pub(super) use crate::test_support::response_json as body_json;

/// Create a valid daemon_auth_jws bearer token (shared across multiple sub-modules).
fn make_daemon_token(
    server_priv: &josekit::jwk::Jwk,
    server_kid: &str,
    daemon_priv: &josekit::jwk::Jwk,
    daemon_kid: &str,
    request_id: &str,
    aud: &str,
) -> String {
    let request_claims = RequestClaims {
        sub: request_id.into(),
        payload_type: PayloadType::Request,
        exp: 1_900_000_000,
    };
    let request_jwt = sign_jws(&request_claims, server_priv, server_kid).unwrap();

    let outer = DaemonAuthClaims {
        request_jwt,
        aud: aud.into(),
        iat: 1_900_000_000 - 30,
        exp: 1_900_000_000,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&outer, daemon_priv, daemon_kid).unwrap()
}
