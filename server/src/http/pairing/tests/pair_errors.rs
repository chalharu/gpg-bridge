use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json};
use crate::repository::{PairingRow, SigningKeyRow};
use crate::test_support::{MockRepository, TEST_SECRET, make_signing_key_row, make_test_app_state};

use super::{
    build_app, make_client_with_public_key, make_device_assertion_token, make_pairing_token,
};

// ===========================================================================
// pair.rs – additional error path tests
// ===========================================================================

// -- POST /pairing: malformed body (missing field) ----------------------------

#[tokio::test]
async fn pair_device_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    // Body with wrong field name
    let body_json = json!({ "wrong_field": "value" });

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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: invalid public JWK in signing key row ---------------------

#[tokio::test]
async fn pair_device_corrupt_public_key_returns_500() {
    let (priv_server, _, server_kid) = generate_signing_key_pair().unwrap();
    // Create a signing key row with valid private key but invalid public_key
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: "not-a-valid-jwk".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(bad_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    // Sign pairing token with the REAL private key but repo returns bad public_key
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid expired timestamp in pairing record ---------------

#[tokio::test]
async fn pair_device_invalid_expired_format_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-bad-ts";
    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: "not-a-valid-timestamp".to_owned(),
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: consume_pairing DB error ----------------------------------

#[tokio::test]
async fn pair_device_consume_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consume-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("consume_pairing");

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: create_client_pairing DB error ----------------------------

#[tokio::test]
async fn pair_device_create_link_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-link-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("create_client_pairing");

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: expired signing key returns 401 ---------------------------

#[tokio::test]
async fn pair_device_expired_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let expired_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_server).unwrap(),
        created_at: "2020-01-01T00:00:00Z".into(),
        expires_at: "2020-06-01T00:00:00Z".into(), // already expired
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(expired_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- POST /pairing: get_signing_key_by_kid DB error ---------------------------

#[tokio::test]
async fn pair_device_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_signing_key_by_kid");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: get_pairing_by_id DB error --------------------------------

#[tokio::test]
async fn pair_device_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_pairing_by_id");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
