use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;

use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json};
use crate::repository::SigningKeyRow;
use crate::test_support::{MockRepository, TEST_SECRET};

use super::{
    add_client_with_assertion_key, add_unconsumed_pairing, build_test_app,
    make_device_assertion_token, make_pairing_repo, pair_device_status_for_default_client,
    response_status,
};

fn make_server_signing_key_row(
    private_key: String,
    public_key: String,
    server_kid: &str,
    created_at: &str,
    expires_at: &str,
) -> SigningKeyRow {
    SigningKeyRow {
        kid: server_kid.to_owned(),
        private_key,
        public_key,
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        is_active: true,
    }
}

// ===========================================================================
// pair.rs – additional error path tests
// ===========================================================================

#[tokio::test]
async fn pair_device_missing_field_returns_400() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    let app = build_test_app(repo);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let status = response_status(
        app,
        Request::post("/pairing")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
            .body(Body::from(
                serde_json::to_vec(&json!({ "wrong_field": "value" })).unwrap(),
            ))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pair_device_corrupt_public_key_returns_500() {
    let (priv_server, _pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = make_server_signing_key_row(
        encrypted,
        "not-a-valid-jwk".into(),
        &server_kid,
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
    );

    let repo = MockRepository::new(bad_sk);
    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, "pair-test").await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn pair_device_invalid_expired_format_returns_500() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();

    let pairing_id = "pair-bad-ts";
    super::add_pairing(&repo, pairing_id, "not-a-valid-timestamp", None);

    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, pairing_id).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn pair_device_consume_db_error_returns_500() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();

    let pairing_id = "pair-consume-err";
    add_unconsumed_pairing(&repo, pairing_id);
    repo.force_error("consume_pairing");

    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, pairing_id).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn pair_device_create_link_db_error_returns_500() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();

    let pairing_id = "pair-link-err";
    add_unconsumed_pairing(&repo, pairing_id);
    repo.force_error("create_client_pairing");

    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, pairing_id).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn pair_device_expired_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let expired_sk = make_server_signing_key_row(
        encrypted,
        jwk_to_json(&pub_server).unwrap(),
        &server_kid,
        "2020-01-01T00:00:00Z",
        "2020-06-01T00:00:00Z",
    );

    let repo = MockRepository::new(expired_sk);
    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, "pair-test").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pair_device_signing_key_db_error_returns_500() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("get_signing_key_by_kid");

    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, "pair-test").await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn pair_device_get_pairing_db_error_returns_500() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("get_pairing_by_id");

    let status =
        pair_device_status_for_default_client(repo, &priv_server, &server_kid, "pair-test").await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
