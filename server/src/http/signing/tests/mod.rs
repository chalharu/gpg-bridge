use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, PayloadType, RequestClaims, generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{ClientPairingRow, ClientRow, FullRequestRow};
use crate::test_support::{MockRepository, make_signing_key_row};

use super::post_sign_request;

mod delete_request;
mod get_and_result;
mod patch_request;
mod post_request;
mod sign_events;
mod unit_tests;

// ---------------------------------------------------------------------------

const VALID_COORD: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", post(post_sign_request))
        .with_state(state)
}

fn make_signing_repo() -> (josekit::jwk::Jwk, josekit::jwk::Jwk, String, MockRepository) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    (priv_jwk, pub_jwk, kid, MockRepository::new(key_row))
}

fn add_signing_client(repo: &MockRepository, client_id: &str) -> (josekit::jwk::Jwk, String) {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&client_pub).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: client_id.into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".into(),
    });
    (client_priv, client_kid)
}

fn add_signing_client_pairing(repo: &MockRepository, client_id: &str, pairing_id: &str) {
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: client_id.into(),
            pairing_id: pairing_id.into(),
            client_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        });
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
