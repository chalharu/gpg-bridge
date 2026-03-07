use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::routing::{get, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::signing::{get_sign_request, post_sign_result};
use crate::jwt::{
    DeviceAssertionClaims, PayloadType, SignClaims, generate_signing_key_pair, sign_jws,
};
use crate::repository::FullRequestRow;
use crate::test_support::{
    MockRepository, make_signing_key_row, make_test_app_state, make_test_app_state_arc,
};

use super::{
    add_signing_client, add_signing_client_pairing, body_json, make_pending_request,
    make_signing_repo,
};

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

fn get_request_with_auth(token: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri("/sign-request")
        .method("GET")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
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

fn post_result_json(token: &str, body: &serde_json::Value) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri("/sign-result")
        .method("POST")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

// ===========================================================================
// GET /sign-request tests
// ===========================================================================

#[tokio::test]
async fn get_sign_request_returns_empty_when_no_pairings() {
    let (_server_priv, _server_pub, _server_kid, repo) = make_signing_repo();
    let (client_priv, client_kid) = add_signing_client(&repo, "client-1");
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
    let (_server_priv, _server_pub, _server_kid, repo) = make_signing_repo();
    let (client_priv, client_kid) = add_signing_client(&repo, "client-1");
    add_signing_client_pairing(&repo, "client-1", "pair-1");
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
    let (_server_priv, _server_pub, _server_kid, repo) = make_signing_repo();
    let (client_priv, client_kid) = add_signing_client(&repo, "client-1");
    add_signing_client_pairing(&repo, "client-1", "pair-1");
    repo.pending_requests
        .lock()
        .unwrap()
        .push(make_pending_request(
            "req-1",
            "client-1",
            "pair-1",
            Some("enc-data-1"),
        ));
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
    let (priv_jwk, _pub_jwk, kid, mut repo) = make_signing_repo();
    repo.full_request = Mutex::new(Some(make_pending_request(
        "req-1", "client-1", "pair-1", None,
    )));
    let state = make_test_app_state(repo);
    let app = build_result_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let body = json!({ "status": "approved", "signature": "sig-data" });
    let resp = app.oneshot(post_result_json(&token, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_sign_result_approved_missing_signature_returns_400() {
    let (priv_jwk, _pub_jwk, kid, repo) = make_signing_repo();
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
