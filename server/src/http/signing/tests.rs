use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use axum::routing::{delete, get, patch, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, DeviceAssertionClaims, PayloadType, RequestClaims, SignClaims,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{ClientPairingRow, ClientRow, FullRequestRow, RequestRow};
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
    make_test_app_state_arc,
};

use super::handler::{build_e2e_kids_map, build_pairing_ids_map, compute_expiry};
use super::types::E2eKeyItem;
use super::{
    delete_sign_request, get_sign_events, get_sign_request, patch_sign_request, post_sign_request,
    post_sign_result,
};

// ---------------------------------------------------------------------------
// Helpers
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

#[tokio::test]
async fn happy_path_returns_201_with_request_jwt_and_e2e_keys() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let state = make_test_app_state(repo);
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
    let repo_arc: Arc<MockRepository> = Arc::new(repo);
    let state = make_test_app_state_arc(repo_arc.clone());
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
    let app = build_app(make_test_app_state(repo));

    let body = valid_request_body(vec![]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_daemon_public_key_returns_400() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

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
    let app = build_app(make_test_app_state(repo));

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
    let repo = MockRepository {
        pending_count: 5,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_active_signing_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, mut repo) = setup_happy_path();
    repo.active_signing_key_override = Some(None);
    let app = build_app(make_test_app_state(repo));

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
    let app = build_app(make_test_app_state(repo));

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
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn multiple_clients_happy_path() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(sk);

    for (cid, pid) in &[("c1", "p1"), ("c2", "p2")] {
        repo.client_pairings_data
            .lock()
            .unwrap()
            .push(ClientPairingRow {
                client_id: cid.to_string(),
                pairing_id: pid.to_string(),
                client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
            });
        repo.clients
            .lock()
            .unwrap()
            .push(make_client_row_with_enc_key(cid, &format!("ek-{cid}")));
    }

    let app = build_app(make_test_app_state(repo));

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
    let repo = MockRepository {
        force_create_request_error: true,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn audit_log_error_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        force_audit_log_error: true,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn invalid_jwt_token_returns_401() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let body = valid_request_body(vec!["not.a.valid.jwt".to_owned()]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairing_not_in_db_returns_401() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Remove pairings so filter_valid_pairings filters all out.
    repo.client_pairings_data.lock().unwrap().clear();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_below_threshold_passes() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        pending_count: 4, // below MAX_PENDING_REQUESTS_PER_PAIRING (5)
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

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
    let app = build_app(make_test_app_state(repo));

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

// ===========================================================================
// Phase 2: PATCH /sign-request tests
// ===========================================================================

const VALID_COORD_P2: &str = VALID_COORD;

fn build_patch_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", patch(patch_sign_request))
        .with_state(state)
}

/// Create a valid daemon_auth_jws bearer token.
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

fn patch_json(token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri("/sign-request")
        .header("content-type", "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Build a Phase 2 mock repo with daemon auth support.
fn setup_phase2_happy_path() -> (
    josekit::jwk::Jwk,
    String,
    josekit::jwk::Jwk,
    String,
    MockRepository,
) {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    // Required by DaemonAuthJws extractor
    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    // Required by patch_sign_request handler
    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        daemon_enc_public_key: json!({
            "kty": "EC", "crv": "P-256",
            "x": VALID_COORD_P2, "y": VALID_COORD_P2,
            "alg": "ECDH-ES+A256KW"
        })
        .to_string(),
        pairing_ids: r#"{"client-1":"pair-1"}"#.into(),
        e2e_kids: r#"{"client-1":"enc-kid-1"}"#.into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });

    *repo.update_phase2_result.lock().unwrap() = Some(true);

    // Client row (for FCM notification lookup)
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row_with_enc_key("client-1", "enc-kid-1"));

    (server_priv, server_kid, daemon_priv, daemon_kid, repo)
}

fn valid_patch_body() -> serde_json::Value {
    json!({
        "encrypted_payloads": [
            {
                "client_id": "client-1",
                "encrypted_data": "base64-encoded-cipher-text"
            }
        ]
    })
}

#[tokio::test]
async fn patch_happy_path_returns_204() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn patch_persists_audit_log() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    let repo_arc: Arc<MockRepository> = Arc::new(repo);
    let state = make_test_app_state_arc(repo_arc.clone());
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let logs = repo_arc.audit_logs.lock().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event_type, "sign_request_dispatched");
    assert_eq!(logs[0].request_id, "req-1");
}

#[tokio::test]
async fn patch_status_not_created_returns_409() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    // Change status to "pending" so it should be rejected
    repo.full_request.lock().unwrap().as_mut().unwrap().status = "pending".into();
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn patch_client_id_mismatch_returns_400() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    // Body has wrong client_id
    let body = json!({
        "encrypted_payloads": [
            {
                "client_id": "wrong-client",
                "encrypted_data": "data"
            }
        ]
    });
    let status = response_status(app, patch_json(&token, &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_cas_failure_returns_409() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    // CAS update returns false (concurrent modification)
    *repo.update_phase2_result.lock().unwrap() = Some(false);
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn patch_request_not_found_returns_404() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    // Clear full_request so load_request fails
    *repo.full_request.lock().unwrap() = None;
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn patch_missing_auth_returns_401() {
    let (_, _, _, _, repo) = setup_phase2_happy_path();
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let req = Request::builder()
        .method("PATCH")
        .uri("/sign-request")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&valid_patch_body()).unwrap()))
        .unwrap();
    let status = response_status(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_multiple_clients_happy_path() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-2".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-2".into(),
        status: "created".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["c1","c2"]"#.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: r#"{"c1":"p1","c2":"p2"}"#.into(),
        e2e_kids: r#"{"c1":"k1","c2":"k2"}"#.into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });

    *repo.update_phase2_result.lock().unwrap() = Some(true);

    for cid in &["c1", "c2"] {
        repo.clients
            .lock()
            .unwrap()
            .push(make_client_row_with_enc_key(cid, &format!("ek-{cid}")));
    }

    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-2",
        "https://api.example.com/sign-request",
    );
    let body = json!({
        "encrypted_payloads": [
            { "client_id": "c1", "encrypted_data": "data1" },
            { "client_id": "c2", "encrypted_data": "data2" }
        ]
    });
    let status = response_status(app, patch_json(&token, &body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn patch_audit_log_error_still_returns_204() {
    // Audit log failure after a successful CAS update must NOT mask the
    // success — the handler logs a warning and still returns 204.
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    let repo = MockRepository {
        force_audit_log_error: true,
        ..repo
    };
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, patch_json(&token, &valid_patch_body())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn patch_duplicate_client_id_returns_400() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) = setup_phase2_happy_path();
    let state = make_test_app_state(repo);
    let app = build_patch_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    // Send two payloads with the same client_id
    let body = serde_json::json!({
        "encrypted_payloads": [
            { "client_id": "client-1", "encrypted_data": "data1" },
            { "client_id": "client-1", "encrypted_data": "data2" },
        ]
    });
    let status = response_status(app, patch_json(&token, &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// GET /sign-request & POST /sign-result tests
// ===========================================================================

// ---------------------------------------------------------------------------
// GET /sign-request helpers
// ---------------------------------------------------------------------------

fn build_get_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", get(get_sign_request))
        .with_state(state)
}

fn make_device_assertion(priv_jwk: &josekit::jwk::Jwk, kid: &str, sub: &str, path: &str) -> String {
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

fn get_request_with_auth(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/sign-request")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// POST /sign-result helpers
// ---------------------------------------------------------------------------

fn build_result_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-result", post(post_sign_result))
        .with_state(state)
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
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

// ===========================================================================
// GET /sign-request tests
// ===========================================================================

#[tokio::test]
async fn get_sign_request_returns_empty_when_no_pairings() {
    // Client key pair (for DeviceAssertionAuth)
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    // Server signing key (for issuing sign_jwt inside handler)
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(key_row);
    let pub_json = jwk_to_json(&client_pub).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "client-1".into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".into(),
    });
    // No pairings → empty response
    let state = make_test_app_state(repo);
    let app = build_get_app(state);

    let token = make_device_assertion(&client_priv, &client_kid, "client-1", "/sign-request");
    let resp = app.oneshot(get_request_with_auth(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["requests"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn get_sign_request_returns_empty_when_no_pending_requests() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(key_row);
    let pub_json = jwk_to_json(&client_pub).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "client-1".into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".into(),
    });
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "client-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        });
    // No pending requests
    let state = make_test_app_state(repo);
    let app = build_get_app(state);

    let token = make_device_assertion(&client_priv, &client_kid, "client-1", "/sign-request");
    let resp = app.oneshot(get_request_with_auth(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["requests"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn get_sign_request_returns_pending_request_items() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(key_row);
    let pub_json = jwk_to_json(&client_pub).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "client-1".into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".into(),
    });
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "client-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        });
    repo.pending_requests.lock().unwrap().push(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: "{}".into(),
        daemon_enc_public_key: r#"{"kty":"EC","crv":"P-256"}"#.into(),
        pairing_ids: r#"{"client-1":"pair-1"}"#.into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: Some(
            r#"[{"client_id":"client-1","encrypted_data":"enc-data-1"}]"#.into(),
        ),
        unavailable_client_ids: "[]".into(),
    });
    let state = make_test_app_state(repo);
    let app = build_get_app(state);

    let token = make_device_assertion(&client_priv, &client_kid, "client-1", "/sign-request");
    let resp = app.oneshot(get_request_with_auth(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let reqs = json["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0]["request_id"], "req-1");
    assert_eq!(reqs[0]["pairing_id"], "pair-1");
    assert_eq!(reqs[0]["encrypted_payload"], "enc-data-1");
    assert!(reqs[0]["sign_jwt"].as_str().unwrap().contains('.'));
    assert_eq!(reqs[0]["daemon_enc_public_key"]["kty"], "EC");
}

// ===========================================================================
// POST /sign-result tests
// ===========================================================================

#[tokio::test]
async fn post_sign_result_approved_returns_204() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let mut repo = MockRepository::new(key_row);
    repo.full_request = Mutex::new(Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: "{}".into(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    }));
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "approved", "signature": "sig-data" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_sign_result_approved_missing_signature_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "approved" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_sign_result_approved_conflict_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    *repo.approve_result.lock().unwrap() = Some(false); // CAS failure
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "approved", "signature": "sig-data" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_sign_result_denied_returns_204() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let mut repo = MockRepository::new(key_row);
    repo.full_request = Mutex::new(Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: "{}".into(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    }));
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "denied" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_sign_result_denied_conflict_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    *repo.deny_result.lock().unwrap() = Some(false); // CAS failure
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "denied" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_sign_result_unavailable_returns_204() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    // Not all clients unavailable yet
    *repo.add_unavailable_result.lock().unwrap() = Some(Some((
        r#"["client-1"]"#.into(),
        r#"["client-1","client-2"]"#.into(),
    )));
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "unavailable" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_sign_result_unavailable_all_clients_triggers_status_change() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    // All clients now unavailable
    *repo.add_unavailable_result.lock().unwrap() =
        Some(Some((r#"["client-1"]"#.into(), r#"["client-1"]"#.into())));
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "unavailable" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_sign_result_unavailable_duplicate_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    *repo.add_unavailable_result.lock().unwrap() = Some(None); // already present
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "unavailable" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_sign_result_invalid_status_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(key_row);
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "unknown" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_sign_result_approved_writes_audit_log() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let key_row = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = Arc::new(MockRepository::new(key_row));
    repo.full_request.lock().unwrap().replace(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: "{}".into(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });

    let state = make_test_app_state_arc(repo.clone());
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "approved", "signature": "sig-data" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let logs = repo.audit_logs.lock().unwrap();
    assert!(logs.iter().any(|l| l.event_type == "sign_approved"));
}

// ===========================================================================
// DELETE /sign-request tests
// ===========================================================================

fn build_delete_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", delete(delete_sign_request))
        .with_state(state)
}

fn delete_request_with_auth(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/sign-request")
        .method("DELETE")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn setup_delete_happy_path(
    status: &str,
) -> (
    josekit::jwk::Jwk,
    String,
    josekit::jwk::Jwk,
    String,
    MockRepository,
) {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    // Required by DaemonAuthJws extractor
    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: status.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    // Required by delete handler (get_full_request_by_id)
    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: status.into(),
        expired: "2027-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: r#"{"client-1":"pair-1"}"#.into(),
        e2e_kids: r#"{"client-1":"enc-kid-1"}"#.into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });

    *repo.delete_request_result.lock().unwrap() = Some(true);

    (server_priv, server_kid, daemon_priv, daemon_kid, repo)
}

#[tokio::test]
async fn delete_created_request_returns_204() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("created");
    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_pending_request_returns_204() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("pending");

    // Add encrypted_payloads so FCM cancel path is exercised
    repo.full_request
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .encrypted_payloads = Some(r#"[{"client_id":"client-1","encrypted_data":"data"}]"#.into());

    // Add client for FCM lookup
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row_with_enc_key("client-1", "enc-kid-1"));

    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_approved_request_returns_409() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("approved");
    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_denied_request_returns_409() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("denied");
    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_unavailable_request_returns_409() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("unavailable");
    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_not_found_returns_404() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    // DaemonAuthJws extractor needs a request row
    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    // But full_request is None → 404
    *repo.full_request.lock().unwrap() = None;

    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_missing_auth_returns_401() {
    let (_, _, _, _, repo) = setup_delete_happy_path("created");
    let state = make_test_app_state(repo);
    let app = build_delete_app(state);

    let req = Request::builder()
        .method("DELETE")
        .uri("/sign-request")
        .body(Body::empty())
        .unwrap();
    let status = response_status(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_writes_audit_log() {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo) =
        setup_delete_happy_path("created");
    let repo_arc: Arc<MockRepository> = Arc::new(repo);
    let state = make_test_app_state_arc(repo_arc.clone());
    let app = build_delete_app(state);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/sign-request",
    );
    let status = response_status(app, delete_request_with_auth(&token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let logs = repo_arc.audit_logs.lock().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event_type, "sign_cancelled");
    assert_eq!(logs[0].request_id, "req-1");
}

// ===========================================================================
// GET /sign-events (SSE) tests
// ===========================================================================

fn build_sign_events_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-events", get(get_sign_events))
        .with_state(state)
}

fn sign_events_request(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/sign-events")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Forwarded-For", "10.0.0.1")
        .body(Body::empty())
        .unwrap()
}

fn make_sign_events_aud() -> String {
    "https://api.example.com/sign-events".to_owned()
}

fn setup_sign_events(status: &str, signature: Option<&str>) -> (String, MockRepository) {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: status.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: status.into(),
        expired: "2099-01-01T00:00:00Z".into(),
        signature: signature.map(|s| s.to_owned()),
        client_ids: r#"["client-1"]"#.into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        &make_sign_events_aud(),
    );

    (token, repo)
}

#[tokio::test]
async fn sign_events_approved_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("approved", Some("sig-data"));
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "expected SSE content-type, got: {ct}"
    );

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        body_str.contains("event: signature"),
        "expected signature event in: {body_str}"
    );
    assert!(
        body_str.contains("sig-data"),
        "expected signature data in: {body_str}"
    );
    assert!(
        body_str.contains("approved"),
        "expected approved status in: {body_str}"
    );
}

#[tokio::test]
async fn sign_events_denied_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("denied", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        body_str.contains("event: signature"),
        "expected signature event in: {body_str}"
    );
    assert!(
        body_str.contains("denied"),
        "expected denied status in: {body_str}"
    );
}

#[tokio::test]
async fn sign_events_unavailable_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("unavailable", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        body_str.contains("unavailable"),
        "expected unavailable status in: {body_str}"
    );
}

#[tokio::test]
async fn sign_events_missing_auth_returns_401() {
    let (_, repo) = setup_sign_events("created", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let req = Request::builder()
        .uri("/sign-events")
        .method("GET")
        .header("X-Forwarded-For", "10.0.0.1")
        .body(Body::empty())
        .unwrap();
    let status = response_status(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sign_events_request_not_found_returns_404() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);

    // DaemonAuth extractor needs a request row
    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });

    // But full_request is None → 404
    *repo.full_request.lock().unwrap() = None;

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        &make_sign_events_aud(),
    );

    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);
    let status = response_status(app, sign_events_request(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sign_events_pending_returns_sse_stream() {
    let (token, repo) = setup_sign_events("pending", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "expected SSE content-type, got: {ct}"
    );
}
