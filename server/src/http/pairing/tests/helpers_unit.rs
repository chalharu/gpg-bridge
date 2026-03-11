use axum::http::StatusCode;
use tower::ServiceExt;

use crate::http::pairing::helpers::{
    build_client_jwt_token, remove_pairing_and_cleanup, verify_pairing_ownership,
};
use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json};
use crate::repository::SigningKeyRow;
use crate::test_support::{
    MockRepository, TEST_SECRET, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{
    add_client_pairing, build_test_app, delete_pairing_by_daemon_request, make_pairing_repo,
};

// ===========================================================================
// helpers.rs – direct unit tests for error paths
// ===========================================================================

// -- build_client_jwt_token: decrypt_private_key fails -------------------------

#[tokio::test]
async fn build_client_jwt_decrypt_error_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "not-valid-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: private JWK parse fails ---------------------------

#[tokio::test]
async fn build_client_jwt_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    // Encrypt a valid JSON that is NOT a JWK
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: public JWK parse fails ----------------------------

#[tokio::test]
async fn build_client_jwt_invalid_public_key_returns_500() {
    let (priv_jwk, _, kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_jwk).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: "not-valid-json".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- verify_pairing_ownership: DB error in get_client_pairings -----------------

#[tokio::test]
async fn verify_ownership_db_error_returns_500() {
    let (_, _, _, repo) = make_pairing_repo();
    repo.force_error("get_client_pairings");
    add_client_pairing(&repo, "fid-1", "pair-1");
    let state = make_test_app_state(repo);

    let result = verify_pairing_ownership(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- remove_pairing_and_cleanup: DB error --------------------------------------

#[tokio::test]
async fn remove_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("delete_client_pairing_and_cleanup");
    let state = make_test_app_state(repo);

    let result = remove_pairing_and_cleanup(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- verify_pairing_ownership DB error through DELETE /pairing endpoint --------

#[tokio::test]
async fn delete_by_daemon_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("get_client_pairings");
    let app = build_test_app(repo);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let response = app
        .oneshot(delete_pairing_by_daemon_request(&client_jwt))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- remove_pairing_and_cleanup DB error through DELETE /pairing endpoint ------

#[tokio::test]
async fn delete_by_daemon_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("delete_client_pairing_and_cleanup");
    add_client_pairing(&repo, "fid-1", "pair-1");
    let app = build_test_app(repo);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let response = app
        .oneshot(delete_pairing_by_daemon_request(&client_jwt))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
