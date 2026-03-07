use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::ClientPairingRow;
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{
    add_client_pairing, add_client_with_assertion_key, add_pairing, build_app,
    delete_pairing_by_phone_request, get_pairing_token_request, make_device_assertion_token,
    make_pairing_repo, make_pairing_token, pair_device_request,
};

// ===========================================================================
// GET /pairing-token
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_returns_200_with_token() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app.oneshot(get_pairing_token_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["pairing_token"].as_str().is_some());
    assert_eq!(json["expires_in"], 300);
}

#[tokio::test]
async fn get_pairing_token_returns_429_when_limit_reached() {
    let (_priv_server, _pub_server, _server_kid, mut repo) = make_pairing_repo();
    repo.forced_unconsumed_count = Some(100); // matches unconsumed_pairing_limit
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app.oneshot(get_pairing_token_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===========================================================================
// POST /pairing
// ===========================================================================

#[tokio::test]
async fn pair_device_returns_200_with_pairing_id() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let pairing_id = "pair-test-1";
    let future_expired = "2099-01-01T00:00:00+00:00";

    add_pairing(&repo, pairing_id, future_expired, None);

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let response = app
        .oneshot(pair_device_request(&pairing_token, &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["pairing_id"], pairing_id);
    assert_eq!(json["ok"], true);
    assert_eq!(json["client_id"], "fid-1");
}

#[tokio::test]
async fn pair_device_expired_pairing_returns_410() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let pairing_id = "pair-expired";
    let past_expired = "2020-01-01T00:00:00+00:00";

    add_pairing(&repo, pairing_id, past_expired, None);

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let response = app
        .oneshot(pair_device_request(&pairing_token, &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn pair_device_already_consumed_returns_409() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let pairing_id = "pair-consumed";
    let future_expired = "2099-01-01T00:00:00+00:00";

    add_pairing(&repo, pairing_id, future_expired, Some("other-client"));

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let response = app
        .oneshot(pair_device_request(&pairing_token, &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ===========================================================================
// DELETE /pairing/{pairing_id}  (by phone)
// ===========================================================================

#[tokio::test]
async fn delete_by_phone_returns_204() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    add_client_pairing(&repo, "fid-1", "pair-del");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(delete_pairing_by_phone_request(
            "pair-del",
            &device_assertion,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_by_phone_not_found_returns_404() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    // No client_pairings → not found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/nonexistent");

    let response = app
        .oneshot(delete_pairing_by_phone_request(
            "nonexistent",
            &device_assertion,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// DELETE /pairing  (by daemon)
// ===========================================================================

#[tokio::test]
async fn delete_by_daemon_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-daemon-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-daemon-del",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ===========================================================================
// POST /pairing/refresh
// ===========================================================================

#[tokio::test]
async fn refresh_returns_200_with_new_jwt() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["client_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    // No client_pairings → not found after JWT verification

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
