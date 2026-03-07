use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::ClientPairingRow;
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{
    add_client_pairing, add_client_with_assertion_key, build_app, delete_pairing_by_daemon_request,
    get_pairing_token_request, make_client_row, make_client_with_public_key,
    make_device_assertion_token, make_pairing_repo, make_pairing_token, pair_device_request,
};

// ===========================================================================
// Additional coverage tests
// ===========================================================================

// -- GET /pairing-token: no active signing key --------------------------------

#[tokio::test]
async fn get_pairing_token_no_signing_key_returns_500() {
    let (_priv_server, _pub_server, _server_kid, mut repo) = make_pairing_repo();
    repo.signing_key = None; // no active key
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app.oneshot(get_pairing_token_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid pairing_token format ------------------------------

#[tokio::test]
async fn pair_device_invalid_token_format_returns_400() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");

    let response = app
        .oneshot(pair_device_request("not-a-valid-jwt", &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: unknown signing key in pairing_token ----------------------

#[tokio::test]
async fn pair_device_unknown_signing_key_returns_400() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();

    // Generate a DIFFERENT key pair to sign the pairing token
    let (priv_other, _pub_other, other_kid, _) = make_pairing_repo();

    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    // Sign the pairing token with the OTHER key (kid won't match repo)
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let response = app
        .oneshot(pair_device_request(&pairing_token, &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: pairing not found in DB -----------------------------------

#[tokio::test]
async fn pair_device_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No pairing record in DB — pairing_id from JWT won't be found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");
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

// -- DELETE /pairing (daemon): invalid JWT format -----------------------------

#[tokio::test]
async fn delete_by_daemon_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "not-a-valid-jwt" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing (daemon): pairing not found ------------------------------

#[tokio::test]
async fn delete_by_daemon_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    // No client_pairings → not found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let response = app
        .oneshot(delete_pairing_by_daemon_request(&client_jwt))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- DELETE /pairing (daemon): last pairing triggers client cleanup -----------

#[tokio::test]
async fn delete_by_daemon_last_pairing_deletes_client() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    add_client_pairing(&repo, "fid-1", "pair-only");

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-only");
    let response = app
        .oneshot(delete_pairing_by_daemon_request(&client_jwt))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing/{pairing_id} (phone): last pairing triggers client cleanup

#[tokio::test]
async fn delete_by_phone_last_pairing_deletes_client() {
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
            pairing_id: "pair-only".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-only");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-only")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing (daemon): multiple pairings, only one removed ------------

#[tokio::test]
async fn delete_by_daemon_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-a");
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

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}

// -- POST /pairing/refresh: invalid JWT format --------------------------------

#[tokio::test]
async fn refresh_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "garbage-token" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing/{pairing_id} (phone): multiple pairings, keep client -----

#[tokio::test]
async fn delete_by_phone_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-a");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-a")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}
