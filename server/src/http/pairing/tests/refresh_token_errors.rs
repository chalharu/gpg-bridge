use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;

use crate::jwt::{encrypt_private_key, generate_signing_key_pair, jwk_to_json};
use crate::repository::SigningKeyRow;
use crate::test_support::{MockRepository, TEST_SECRET};

use super::{
    add_client_pairing, add_client_with_assertion_key, build_test_app,
    delete_pairing_by_phone_request_for, get_pairing_token_request, make_pairing_repo,
    refresh_pairing_json_request, refresh_pairing_request_for, response_status,
};

// ===========================================================================
// refresh.rs – additional error path tests
// ===========================================================================

#[tokio::test]
async fn refresh_missing_field_returns_400() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let status = response_status(
        build_test_app(repo),
        refresh_pairing_json_request(json!({ "wrong_field": "value" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refresh_signing_key_disappears_returns_500() {
    let (priv_server, pub_server, server_kid, mut repo) = make_pairing_repo();
    repo.signing_key_by_kid_max_success = Some(1);
    add_client_pairing(&repo, "fid-1", "pair-refresh");

    let status = response_status(
        build_test_app(repo),
        refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-refresh",
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn refresh_update_not_found_returns_404() {
    let (priv_server, pub_server, server_kid, mut repo) = make_pairing_repo();
    repo.force_update_false = true;
    add_client_pairing(&repo, "fid-1", "pair-refresh");

    let status = response_status(
        build_test_app(repo),
        refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-refresh",
        ),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn refresh_update_db_error_returns_500() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("update_client_jwt_issued_at");
    add_client_pairing(&repo, "fid-1", "pair-refresh");

    let status = response_status(
        build_test_app(repo),
        refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-refresh",
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn refresh_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    repo.force_error("get_client_pairings");

    let status = response_status(
        build_test_app(repo),
        refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-refresh",
        ),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// token.rs – additional error path tests
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_count_db_error_returns_500() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    repo.force_error("count_unconsumed_pairings");

    let status = response_status(build_test_app(repo), get_pairing_token_request()).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn get_pairing_token_create_pairing_db_error_returns_500() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    repo.force_error("create_pairing");

    let status = response_status(build_test_app(repo), get_pairing_token_request()).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

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

    let status = response_status(
        build_test_app(MockRepository::new(bad_sk)),
        get_pairing_token_request(),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

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

    let status = response_status(
        build_test_app(MockRepository::new(bad_sk)),
        get_pairing_token_request(),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// delete.rs – additional error path tests
// ===========================================================================

#[tokio::test]
async fn delete_by_daemon_malformed_body_returns_400() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let status = response_status(
        build_test_app(repo),
        Request::delete("/pairing")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({ "wrong_field": "value" })).unwrap(),
            ))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_by_phone_ownership_db_error_returns_500() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    repo.force_error("get_client_pairings");

    let status = response_status(
        build_test_app(repo),
        delete_pairing_by_phone_request_for("pair-1", &priv_client, &client_kid, "fid-1"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_by_phone_cleanup_db_error_returns_500() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    add_client_pairing(&repo, "fid-1", "pair-del");
    repo.force_error("delete_client_pairing_and_cleanup");

    let status = response_status(
        build_test_app(repo),
        delete_pairing_by_phone_request_for("pair-del", &priv_client, &client_kid, "fid-1"),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
