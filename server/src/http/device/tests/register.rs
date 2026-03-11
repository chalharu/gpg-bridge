use std::sync::Arc;

use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use crate::repository::{SignatureRepository, SigningKeyRepository};
use crate::test_support::{make_test_app_state_arc, response_json};

use super::{
    DeviceAppFixture, X_COORD, Y_COORD, authed_json_request, authed_request,
    build_refresh_device_jwt_app, build_sqlite_device_app_with_client, build_test_router,
    build_test_sqlite_repo, json_request, make_client_row, make_device_assertion,
    make_device_key_test_setup, make_device_sig_only_test_setup, make_signing_key_row,
    post_device_json_request, register_body, sign_device_jwt,
};

fn post_device_request(body: serde_json::Value) -> Request<Body> {
    json_request(Method::POST, "/device", &body)
}

#[tokio::test]
async fn register_device_success() {
    let fixture = DeviceAppFixture::new().await;

    let body = register_body("fid-1", "token-1");
    let response = fixture
        .app
        .oneshot(post_device_request(body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = response_json(response).await;
    assert!(json["device_jwt"].as_str().is_some());
}

#[tokio::test]
async fn register_device_fid_conflict() {
    let client = make_client_row("fid-1", "old-token", "[]", "kid-1");
    let fixture = DeviceAppFixture::with_client(&client).await;

    let body = register_body("fid-1", "token-1");
    let response = fixture
        .app
        .oneshot(post_device_request(body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_token_conflict() {
    let client = make_client_row("other-fid", "shared-token", "[]", "kid-1");
    let fixture = DeviceAppFixture::with_client(&client).await;

    let body = register_body("fid-1", "shared-token");
    let response = fixture
        .app
        .oneshot(post_device_request(body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_without_active_signing_key_returns_500() {
    let repo = build_test_sqlite_repo().await;
    let app = build_test_router(make_test_app_state_arc(
        repo as Arc<dyn SignatureRepository>,
    ));

    let body = register_body("fid-no-key", "token-no-key");
    let response = app.oneshot(post_device_request(body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(response).await;
    assert_eq!(body["detail"], "no active signing key");
    assert_eq!(body["instance"], serde_json::Value::Null);
}

#[tokio::test]
async fn register_device_with_invalid_stored_signing_key_returns_500() {
    let (mut sk, _) = make_signing_key_row();
    sk.private_key = "not-an-encrypted-jwk".to_owned();
    let repo = build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let body = register_body("fid-invalid-key", "token-invalid-key");
    let response = app.oneshot(post_device_request(body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(response).await;
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("failed to decrypt signing key")
    );
}

#[tokio::test]
async fn register_device_missing_sig_keys() {
    let fixture = DeviceAppFixture::new().await;

    let body = json!({
        "device_token": "t",
        "firebase_installation_id": "fid-1",
        "public_key": { "keys": { "sig": [], "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }] } }
    });
    let response = fixture
        .app
        .oneshot(post_device_request(body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_device_invalid_sig_key_alg() {
    let fixture = DeviceAppFixture::new().await;

    let body = json!({
        "device_token": "t",
        "firebase_installation_id": "fid-1",
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "RS256", "x": X_COORD, "y": Y_COORD }],
                "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }]
            }
        }
    });
    let response = fixture
        .app
        .oneshot(post_device_request(body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// PATCH /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_device_token_success() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let client = make_client_row("fid-1", "old-token", &keys, &enc_kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-token" });
    let response = app
        .oneshot(authed_json_request(Method::PATCH, "/device", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_success() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let client = make_client_row("fid-1", "tok", &keys, &enc_kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": enc_kid });
    let response = app
        .oneshot(authed_json_request(Method::PATCH, "/device", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_not_found_returns_400() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let client = make_client_row("fid-1", "tok", &keys, &enc_kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": "nonexistent-kid" });
    let response = app
        .oneshot(authed_json_request(Method::PATCH, "/device", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_device_both_fields_success() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let client = make_client_row("fid-1", "old-tok", &keys, &enc_kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-tok", "default_kid": enc_kid });
    let response = app
        .oneshot(authed_json_request(Method::PATCH, "/device", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_empty_body_returns_400() {
    let (priv_jwk, kid, sk, keys) = make_device_sig_only_test_setup();
    let client = make_client_row("fid-2", "tok", &keys, &kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-2", "/device");
    let body = json!({});
    let response = app
        .oneshot(authed_json_request(Method::PATCH, "/device", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// DELETE /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_device_success() {
    let (priv_jwk, kid, sk, keys) = make_device_sig_only_test_setup();
    let client = make_client_row("fid-3", "tok", &keys, &kid);
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-3", "/device");
    let response = app
        .oneshot(authed_request(Method::DELETE, "/device", &token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// POST /device/refresh tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_device_jwt_success() {
    let (client_priv, client_kid, sk, _repo, app) =
        build_refresh_device_jwt_app("fid-4", None).await;
    let old_device_jwt = sign_device_jwt(&sk, "fid-4");

    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-4", "/device/refresh");
    let body = json!({ "device_jwt": old_device_jwt });
    let response = app
        .oneshot(post_device_json_request(
            "/device/refresh",
            &assertion,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["device_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_device_jwt_sub_mismatch_returns_401() {
    let (client_priv, client_kid, sk, _repo, app) =
        build_refresh_device_jwt_app("fid-5", None).await;
    let old_jwt = sign_device_jwt(&sk, "wrong-fid");

    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-5", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(post_device_json_request(
            "/device/refresh",
            &assertion,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_device_jwt_expired_issued_at_returns_401() {
    let (client_priv, client_kid, sk, _repo, app) =
        build_refresh_device_jwt_app("fid-6", Some("2020-01-01T00:00:00+00:00")).await;
    let old_jwt = sign_device_jwt(&sk, "fid-6");

    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-6", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(post_device_json_request(
            "/device/refresh",
            &assertion,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
