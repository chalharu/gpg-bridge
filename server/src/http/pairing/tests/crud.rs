use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::{ClientPairingRow, PairingRow};
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{
    build_app, make_client_with_public_key, make_device_assertion_token, make_pairing_token,
};

// ===========================================================================
// GET /pairing-token
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_returns_200_with_token() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

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
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let mut repo = MockRepository::new(sk);
    repo.forced_unconsumed_count = Some(100); // matches unconsumed_pairing_limit
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===========================================================================
// POST /pairing
// ===========================================================================

#[tokio::test]
async fn pair_device_returns_200_with_pairing_id() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-test-1";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
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
    assert_eq!(json["pairing_id"], pairing_id);
    assert_eq!(json["ok"], true);
    assert_eq!(json["client_id"], "fid-1");
}

#[tokio::test]
async fn pair_device_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-expired";
    let past_expired = "2020-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: past_expired.to_owned(),
        client_id: None,
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn pair_device_already_consumed_returns_409() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consumed";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: Some("other-client".to_owned()), // already consumed
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ===========================================================================
// DELETE /pairing/{pairing_id}  (by phone)
// ===========================================================================

#[tokio::test]
async fn delete_by_phone_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-del")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_by_phone_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No client_pairings → not found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/nonexistent");

    let response = app
        .oneshot(
            Request::delete("/pairing/nonexistent")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
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
