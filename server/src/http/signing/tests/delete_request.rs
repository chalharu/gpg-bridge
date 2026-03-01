use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::delete;

use crate::http::AppState;
use crate::http::signing::delete_sign_request;
use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::{FullRequestRow, RequestRow};
use crate::test_support::{
    MockRepository, make_signing_key_row, make_test_app_state, make_test_app_state_arc,
};

use super::{make_client_row_with_enc_key, make_daemon_token, response_status};

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
