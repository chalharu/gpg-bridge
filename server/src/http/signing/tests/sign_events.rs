use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;

use tower::ServiceExt;

use crate::http::AppState;
use crate::http::signing::get_sign_events;
use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::{FullRequestRow, RequestRow};
use crate::test_support::{
    MockRepository, make_signing_key_row, make_test_app_state, make_test_app_state_arc,
    response_body_string,
};

use super::{make_daemon_token, response_status};

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

    let body_str = response_body_string(resp).await;
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

    let body_str = response_body_string(resp).await;
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

    let body_str = response_body_string(resp).await;
    assert!(
        body_str.contains("unavailable"),
        "expected unavailable status in: {body_str}"
    );
}

#[tokio::test]
async fn sign_events_cancelled_returns_immediate_sse() {
    let (token, repo) = setup_sign_events("cancelled", None);
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let resp = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_str = response_body_string(resp).await;
    assert!(
        body_str.contains("cancelled"),
        "expected cancelled status in: {body_str}"
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
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = super::body_json(response).await;
    assert_eq!(body["detail"], "missing authorization token");
    assert_eq!(body["instance"], "/sign-events");
}

#[tokio::test]
async fn sign_events_wrong_aud_returns_401_with_route_instance() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = MockRepository::new(sk);
    *repo.request.lock().unwrap() = Some(RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    });
    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        expired: "2099-01-01T00:00:00Z".into(),
        signature: None,
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
        "https://api.example.com/wrong",
    );

    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);
    let response = app.oneshot(sign_events_request(&token)).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = super::body_json(response).await;
    assert_eq!(body["detail"], "invalid token: aud mismatch");
    assert_eq!(body["instance"], "/sign-events");
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

    let body_str = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response_body_string(response),
    )
    .await
    .expect("timed out reading SSE body");
    assert!(
        body_str.contains("sig-notified"),
        "expected notified signature in: {body_str}"
    );
    assert!(
        body_str.contains("approved"),
        "expected approved status in: {body_str}"
    );
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

    let body_str = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        response_body_string(response),
    )
    .await
    .expect("timed out reading SSE body");
    assert!(
        body_str.contains("denied"),
        "expected DB fallback status in: {body_str}"
    );
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
    assert_eq!(body["detail"], "could not determine client IP");
    assert_eq!(body["instance"], "/sign-events");
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
    assert_eq!(
        body["detail"],
        "SSE connection already active for this request"
    );
    assert_eq!(body["instance"], "/sign-events");

    drop(first);
}

#[tokio::test]
async fn sign_events_invalid_expiry_returns_500_with_instance() {
    let (token, repo) = setup_sign_events("pending", None);
    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "not-a-date".into(),
        signature: None,
        client_ids: r#"[\"client-1\"]"#.into(),
        daemon_public_key: repo
            .request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .daemon_public_key
            .clone(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });
    let state = make_test_app_state(repo);
    let app = build_sign_events_app(state);

    let response = app.oneshot(sign_events_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = super::body_json(response).await;
    assert_eq!(body["instance"], "/sign-events");
}

#[tokio::test]
async fn sign_events_expired_stream_emits_expired_event_and_writes_audit_log() {
    let (token, repo) = setup_sign_events("pending", None);
    let repo = Arc::new(repo);
    *repo.full_request.lock().unwrap() = Some(FullRequestRow {
        request_id: "req-1".into(),
        status: "pending".into(),
        expired: "2020-01-01T00:00:00Z".into(),
        signature: None,
        client_ids: r#"[\"client-1\"]"#.into(),
        daemon_public_key: repo
            .request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .daemon_public_key
            .clone(),
        daemon_enc_public_key: "{}".into(),
        pairing_ids: "{}".into(),
        e2e_kids: "{}".into(),
        encrypted_payloads: None,
        unavailable_client_ids: "[]".into(),
    });
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
