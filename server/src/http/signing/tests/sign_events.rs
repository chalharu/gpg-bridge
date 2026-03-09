use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;

use tower::ServiceExt;

use crate::http::AppState;
use crate::http::signing::get_sign_events;
use crate::test_support::{
    MockRepository, assert_problem_details, make_test_app_state, make_test_app_state_arc,
    response_body_string,
};

use super::{
    make_daemon_auth_full_request_row, make_daemon_auth_repo, make_daemon_token, response_status,
    seed_daemon_auth_request,
};

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

fn set_full_request_status(repo: &MockRepository, status: &str, signature: Option<&str>) {
    let mut full_request = repo.full_request.lock().unwrap();
    let row = full_request.as_mut().unwrap();
    row.status = status.to_owned();
    row.signature = signature.map(str::to_owned);
}

fn make_sign_events_aud() -> String {
    "https://api.example.com/sign-events".to_owned()
}

fn replace_sign_events_full_request(
    repo: &MockRepository,
    status: &str,
    expired: &str,
    signature: Option<&str>,
) {
    let daemon_public_key = repo
        .request
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .daemon_public_key
        .clone();
    *repo.full_request.lock().unwrap() = Some(make_daemon_auth_full_request_row(
        "req-1",
        status,
        expired,
        signature,
        daemon_public_key,
    ));
}

fn setup_sign_events_with_aud(
    status: &str,
    expired: &str,
    signature: Option<&str>,
    aud: &str,
) -> (String, MockRepository) {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo, daemon_public_key) =
        make_daemon_auth_repo();

    seed_daemon_auth_request(
        &repo,
        "req-1",
        status,
        &daemon_public_key,
        Some(make_daemon_auth_full_request_row(
            "req-1",
            status,
            expired,
            signature,
            daemon_public_key.clone(),
        )),
    );

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        aud,
    );

    (token, repo)
}

fn setup_sign_events_request_only(status: &str, aud: &str) -> (String, MockRepository) {
    let (server_priv, server_kid, daemon_priv, daemon_kid, repo, daemon_public_key) =
        make_daemon_auth_repo();

    seed_daemon_auth_request(&repo, "req-1", status, &daemon_public_key, None);

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        aud,
    );

    (token, repo)
}

fn setup_sign_events(status: &str, signature: Option<&str>) -> (String, MockRepository) {
    setup_sign_events_with_aud(
        status,
        "2099-01-01T00:00:00Z",
        signature,
        &make_sign_events_aud(),
    )
}

async fn assert_sign_events_sse(response: axum::response::Response, expected: &[&str]) {
    let body_str = response_body_string(response).await;
    assert!(
        body_str.contains("event: signature"),
        "expected signature event in: {body_str}"
    );
    for expected_value in expected {
        assert!(
            body_str.contains(expected_value),
            "expected {expected_value} in: {body_str}"
        );
    }
}

async fn assert_sign_events_sse_with_timeout(
    response: axum::response::Response,
    expected: &[&str],
) {
    let body_str = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response_body_string(response),
    )
    .await
    .expect("timed out reading SSE body");
    assert!(
        body_str.contains("event: signature"),
        "expected signature event in: {body_str}"
    );
    for expected_value in expected {
        assert!(
            body_str.contains(expected_value),
            "expected {expected_value} in: {body_str}"
        );
    }
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

    assert_sign_events_sse(resp, &["sig-data", "approved"]).await;
}

#[tokio::test]
async fn sign_events_denied_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("denied", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_sign_events_sse(resp, &["denied"]).await;
}

#[tokio::test]
async fn sign_events_unavailable_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("unavailable", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_sign_events_sse(resp, &["unavailable"]).await;
}

#[tokio::test]
async fn sign_events_cancelled_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("cancelled", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_sign_events_sse(resp, &["cancelled"]).await;
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
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = super::body_json(response).await;
    assert_problem_details(&body, "missing authorization token", "/sign-events");
}

#[tokio::test]
async fn sign_events_wrong_aud_returns_401_with_route_instance() {
    let (token, repo) = setup_sign_events_with_aud(
        "created",
        "2099-01-01T00:00:00Z",
        None,
        "https://api.example.com/wrong",
    );
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);
    let response = app.oneshot(sign_events_request(&token)).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = super::body_json(response).await;
    assert_problem_details(&body, "invalid token: aud mismatch", "/sign-events");
}

#[tokio::test]
async fn sign_events_request_not_found_returns_404() {
    let (token, repo) = setup_sign_events_request_only("created", &make_sign_events_aud());
    *repo.full_request.lock().unwrap() = None;

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

#[tokio::test]
async fn sign_events_notify_delivers_signature_event_on_waiting_stream() {
    let (token, repo) = setup_sign_events("pending", None);
    let state = make_test_app_state(repo);
    let notifier = state.sign_event_notifier.clone();
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    notifier.notify(
        "req-1",
        crate::http::signing::notifier::SignEventData {
            signature: Some("sig-notified".to_owned()),
            status: "approved".to_owned(),
        },
    );

    assert_sign_events_sse_with_timeout(response, &["sig-notified", "approved"]).await;
}

#[tokio::test]
async fn sign_events_closed_stream_checks_db_fallback() {
    let (token, repo) = setup_sign_events("pending", None);
    let repo = Arc::new(repo);
    let state = make_test_app_state_arc(repo.clone());
    let notifier = state.sign_event_notifier.clone();
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    set_full_request_status(repo.as_ref(), "denied", None);
    notifier.unsubscribe("req-1");

    assert_sign_events_sse_with_timeout(response, &["denied"]).await;
}

#[tokio::test]
async fn sign_events_closed_stream_emits_closed_comment_when_request_stays_pending() {
    let (token, repo) = setup_sign_events("pending", None);
    let state = make_test_app_state(repo);
    let notifier = state.sign_event_notifier.clone();
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    notifier.unsubscribe("req-1");

    let body_str = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response_body_string(response),
    )
    .await
    .expect("timed out reading SSE body");
    assert!(
        body_str.contains("closed"),
        "expected closed comment in: {body_str}"
    );
}

#[tokio::test]
async fn sign_events_missing_client_ip_returns_500_with_instance() {
    let (token, repo) = setup_sign_events("pending", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let request = Request::builder()
        .uri("/sign-events")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = super::body_json(response).await;
    assert_problem_details(&body, "could not determine client IP", "/sign-events");
}

#[tokio::test]
async fn sign_events_duplicate_connection_returns_429_with_instance() {
    let (token, repo) = setup_sign_events("pending", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let first = app
        .clone()
        .oneshot(sign_events_request(&token))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let body = super::body_json(response).await;
    assert_problem_details(
        &body,
        "SSE connection already active for this request",
        "/sign-events",
    );

    drop(first);
}

#[tokio::test]
async fn sign_events_invalid_expiry_returns_500_with_instance() {
    let (token, repo) = setup_sign_events("pending", None);
    replace_sign_events_full_request(&repo, "pending", "not-a-date", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = super::body_json(response).await;
    assert_problem_details(&body, "internal server error", "/sign-events");
}

#[tokio::test]
async fn sign_events_expired_stream_emits_expired_event_and_writes_audit_log() {
    let (token, repo) = setup_sign_events("pending", None);
    let repo = Arc::new(repo);
    replace_sign_events_full_request(repo.as_ref(), "pending", "2020-01-01T00:00:00Z", None);
    let state = make_test_app_state_arc(repo.clone());
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_str = response_body_string(response).await;
    assert!(
        body_str.contains("expired"),
        "expected expired event in: {body_str}"
    );

    let logs = repo.audit_logs.lock().unwrap();
    assert!(logs.iter().any(|log| log.event_type == "sign_expired"));
}
