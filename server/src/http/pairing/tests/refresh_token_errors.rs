use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json};
use crate::repository::{ClientPairingRow, SigningKeyRow};
use crate::test_support::{
    MockRepository, TEST_SECRET, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{build_app, make_client_with_public_key, make_device_assertion_token};

// ===========================================================================
// refresh.rs – additional error path tests
// ===========================================================================

// -- POST /pairing/refresh: malformed body ------------------------------------

#[tokio::test]
async fn refresh_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing/refresh: signing key disappears between verify and fetch ---

#[tokio::test]
async fn refresh_signing_key_disappears_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = MockRepository::new(sk);
    // First call to get_signing_key_by_kid succeeds (verify_one_token), second returns None
    repo.signing_key_by_kid_max_success = Some(1);
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at returns false ---------

#[tokio::test]
async fn refresh_update_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = MockRepository::new(sk);
    repo.force_update_false = true;
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at DB error --------------

#[tokio::test]
async fn refresh_update_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.force_error("update_client_jwt_issued_at");
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: get_client_pairings DB error ----------------------

#[tokio::test]
async fn refresh_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.force_error("get_client_pairings");

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// token.rs – additional error path tests
// ===========================================================================

// -- GET /pairing-token: count_unconsumed_pairings DB error -------------------

#[tokio::test]
async fn get_pairing_token_count_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("count_unconsumed_pairings");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: create_pairing DB error ------------------------------

#[tokio::test]
async fn get_pairing_token_create_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("create_pairing");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: bad encrypted private key ----------------------------

#[tokio::test]
async fn get_pairing_token_bad_private_key_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "bad-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: invalid private JWK (decrypts to non-JWK) ------------

#[tokio::test]
async fn get_pairing_token_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing: malformed body ------------------------------------------

#[tokio::test]
async fn delete_by_daemon_malformed_body_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- DELETE /pairing/{pairing_id}: verify_pairing_ownership DB error ----------

#[tokio::test]
async fn delete_by_phone_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_client_pairings");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-1");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-1")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing/{pairing_id}: remove_pairing_and_cleanup DB error --------

#[tokio::test]
async fn delete_by_phone_cleanup_db_error_returns_500() {
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
    repo.force_error("delete_client_pairing_and_cleanup");
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
