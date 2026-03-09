use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::patch;
use serde_json::json;

use crate::http::AppState;
use crate::http::signing::patch_sign_request;
use crate::test_support::{MockRepository, make_test_app_state, make_test_app_state_arc};

use super::{
    VALID_COORD, make_client_row_with_enc_key, make_daemon_auth_full_request_row,
    make_daemon_auth_repo, make_daemon_token, response_status, seed_daemon_auth_request,
    seed_single_client_request_links,
};

// ===========================================================================
// Phase 2: PATCH /sign-request tests
// ===========================================================================

const VALID_COORD_P2: &str = VALID_COORD;

fn build_patch_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-request", patch(patch_sign_request))
        .with_state(state)
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
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo, daemon_public_key) =
        make_daemon_auth_repo();

    let mut full_request = make_daemon_auth_full_request_row(
        "req-1",
        "created",
        "2027-01-01T00:00:00Z",
        None,
        daemon_public_key.clone(),
    );
    full_request.daemon_enc_public_key = json!({
        "kty": "EC", "crv": "P-256",
        "x": VALID_COORD_P2, "y": VALID_COORD_P2,
        "alg": "ECDH-ES+A256KW"
    })
    .to_string();
    seed_single_client_request_links(&mut full_request, "client-1", "pair-1", "enc-kid-1");

    seed_daemon_auth_request(
        &repo,
        "req-1",
        "created",
        &daemon_public_key,
        Some(full_request),
    );

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
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo, daemon_public_key) =
        make_daemon_auth_repo();

    let mut full_request = make_daemon_auth_full_request_row(
        "req-2",
        "created",
        "2027-01-01T00:00:00Z",
        None,
        daemon_public_key.clone(),
    );
    full_request.client_ids = r#"["c1","c2"]"#.into();
    full_request.pairing_ids = r#"{"c1":"p1","c2":"p2"}"#.into();
    full_request.e2e_kids = r#"{"c1":"k1","c2":"k2"}"#.into();

    seed_daemon_auth_request(
        &repo,
        "req-2",
        "created",
        &daemon_public_key,
        Some(full_request),
    );

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
