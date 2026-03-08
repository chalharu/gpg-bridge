use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::pairing::get_pairing_session;
use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::{ClientRow, PairingRow};
use crate::test_support::{MockRepository, make_signing_key_row, make_test_app_state};

use super::{make_pairing_token, response_json};

// ===========================================================================
// GET /pairing-session  (SSE)
// ===========================================================================

fn build_sse_app(state: AppState) -> Router {
    Router::new()
        .route("/pairing-session", get(get_pairing_session))
        .with_state(state)
}

#[tokio::test]
async fn session_missing_auth_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["detail"], "missing authorization token");
    assert_eq!(body["instance"], "/pairing-session");
}

#[tokio::test]
async fn session_invalid_bearer_scheme_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Basic abc123")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["detail"], "missing Bearer scheme");
    assert_eq!(body["instance"], "/pairing-session");
}

#[tokio::test]
async fn session_invalid_authorization_header_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_bytes(b"\xff").unwrap(),
                )
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["detail"], "invalid authorization header");
    assert_eq!(body["instance"], "/pairing-session");
}

#[tokio::test]
async fn session_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Bearer not-a-valid-jwt")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_unknown_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    // Generate a different key pair to sign the token
    let (priv_other, _pub_other, other_kid) = generate_signing_key_pair().unwrap();
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-1");

    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");

    let repo = MockRepository::new(sk);
    // No pairings in repo — get_pairing_by_id returns None
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-expired");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-expired".to_owned(),
        expired: "2020-01-01T00:00:00+00:00".to_owned(), // past date
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_already_paired_returns_sse_with_paired_event() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-done");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-done".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: Some("fid-1".to_owned()),
    });
    // Need a client that exists for the client_jwt build
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-1".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.contains("event: paired"),
        "expected paired event in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_jwt\""),
        "expected client_jwt in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_id\""),
        "expected client_id in body: {body_str}"
    );
}

#[tokio::test]
async fn session_pending_pairing_returns_200_sse_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-pending");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-pending".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // SSE stream starts with 200
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/event-stream"),
        "expected text/event-stream but got: {content_type}"
    );
}

#[tokio::test]
async fn session_missing_client_ip_returns_500_with_instance() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-pending");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-pending".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(response).await;
    assert_eq!(body["detail"], "could not determine client IP");
    assert_eq!(body["instance"], "/pairing-session");
}

#[tokio::test]
async fn session_duplicate_connection_returns_429_with_instance() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-pending");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-pending".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let first = app
        .clone()
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = response_json(response).await;
    assert_eq!(
        body["detail"],
        "SSE connection already active for this pairing"
    );
    assert_eq!(body["instance"], "/pairing-session");

    drop(first);
}

#[tokio::test]
async fn session_invalid_pairing_expiry_returns_500_with_instance() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-invalid-expiry");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-invalid-expiry".to_owned(),
        expired: "not-a-date".to_owned(),
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(response).await;
    assert_eq!(body["instance"], "/pairing-session");
}

#[tokio::test]
async fn session_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = MockRepository::new(sk);
    repo.force_error("get_signing_key_by_kid");
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-1".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    repo.force_error("get_pairing_by_id");
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_notify_delivers_paired_event_on_waiting_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-wait");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-wait".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-w".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_test_app_state(repo);
    let notifier = state.pairing_notifier.clone();

    let app = build_sse_app(state);
    let request = Request::get("/pairing-session")
        .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
        .header("X-Forwarded-For", "10.0.0.1")
        .body(Body::empty())
        .unwrap();

    // Send SSE request — spawns the stream.
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Send the paired notification.
    use crate::http::pairing::notifier::PairedEventData;
    notifier.notify(
        "pair-wait",
        PairedEventData {
            client_jwt: "jwt-val".to_owned(),
            client_id: "fid-w".to_owned(),
        },
    );

    let body_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("timed out reading SSE body")
    .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        body_str.contains("event: paired"),
        "expected paired event: {body_str}"
    );
}
