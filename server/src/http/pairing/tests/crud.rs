use axum::http::StatusCode;
use tower::ServiceExt;

use super::{
    add_client_pairing, add_client_with_assertion_key, add_pairing, build_test_app,
    delete_pairing_by_daemon_request_for, delete_pairing_by_phone_request,
    get_pairing_token_request, make_device_assertion_token, make_pairing_repo, make_pairing_token,
    pair_device_request, pair_device_status_for, refresh_pairing_request_for, response_json,
};

// ===========================================================================
// GET /pairing-token
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_returns_200_with_token() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let app = build_test_app(repo);

    let response = app.oneshot(get_pairing_token_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["pairing_token"].as_str().is_some());
    assert_eq!(json["expires_in"], 300);
}

#[tokio::test]
async fn get_pairing_token_returns_429_when_limit_reached() {
    let (_priv_server, _pub_server, _server_kid, mut repo) = make_pairing_repo();
    repo.forced_unconsumed_count = Some(100); // matches unconsumed_pairing_limit
    let app = build_test_app(repo);

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

    let app = build_test_app(repo);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let response = app
        .oneshot(pair_device_request(&pairing_token, &device_assertion))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["pairing_id"], pairing_id);
    assert_eq!(json["ok"], true);
    assert_eq!(json["client_id"], "fid-1");
}

#[tokio::test]
async fn pair_device_expired_pairing_returns_410() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let pairing_id = "pair-expired";
    add_pairing(&repo, pairing_id, "2020-01-01T00:00:00+00:00", None);

    let status = pair_device_status_for(
        repo,
        &priv_server,
        &server_kid,
        pairing_id,
        &priv_client,
        &client_kid,
        "fid-1",
    )
    .await;

    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn pair_device_already_consumed_returns_409() {
    let (priv_server, _pub_server, server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");

    let pairing_id = "pair-consumed";
    add_pairing(
        &repo,
        pairing_id,
        "2099-01-01T00:00:00+00:00",
        Some("other-client"),
    );

    let status = pair_device_status_for(
        repo,
        &priv_server,
        &server_kid,
        pairing_id,
        &priv_client,
        &client_kid,
        "fid-1",
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
}

// ===========================================================================
// DELETE /pairing/{pairing_id}  (by phone)
// ===========================================================================

#[tokio::test]
async fn delete_by_phone_returns_204() {
    let (_priv_server, _pub_server, _server_kid, repo) = make_pairing_repo();
    let (priv_client, client_kid) = add_client_with_assertion_key(&repo, "fid-1");
    add_client_pairing(&repo, "fid-1", "pair-del");

    let app = build_test_app(repo);

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

    let app = build_test_app(repo);

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
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    add_client_pairing(&repo, "fid-1", "pair-daemon-del");

    let app = build_test_app(repo);

    let response = app
        .oneshot(delete_pairing_by_daemon_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-daemon-del",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ===========================================================================
// POST /pairing/refresh
// ===========================================================================

#[tokio::test]
async fn refresh_returns_200_with_new_jwt() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    add_client_pairing(&repo, "fid-1", "pair-refresh");

    let app = build_test_app(repo);

    let response = app
        .oneshot(refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-refresh",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert!(json["client_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid, repo) = make_pairing_repo();
    // No client_pairings → not found after JWT verification

    let app = build_test_app(repo);

    let response = app
        .oneshot(refresh_pairing_request_for(
            &priv_server,
            &pub_server,
            &server_kid,
            "fid-1",
            "pair-missing",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
