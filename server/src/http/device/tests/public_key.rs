use std::sync::{Arc, Mutex};

use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::{ClientRepository, SignatureRepository, SigningKeyRepository};
use crate::test_support::{MockRepository, make_test_app_state, make_test_app_state_arc};

use super::{
    DeviceAppFixture, X_COORD, Y_COORD, authed_json_request, authed_request, build_test_router,
    build_test_sqlite_repo, make_client_row, make_device_assertion, make_pk_test_setup,
    make_signing_key_row,
};

fn post_public_key_request(token: &str, body: &serde_json::Value) -> Request<Body> {
    authed_json_request(Method::POST, "/device/public_key", token, body)
}

fn get_public_key_request(token: &str) -> Request<Body> {
    authed_request(Method::GET, "/device/public_key", token)
}

#[tokio::test]
async fn add_public_key_sig_success() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_enc_success() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }]
    });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_with_default_kid_change() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": "enc-new"
    });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_public_key_invalid_key_rejected() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "RS256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_empty_keys_rejected() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({ "keys": [] });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_unsupported_use_rejected() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "other", "crv": "P-256", "alg": "ES256", "x": X_COORD, "y": Y_COORD }]
    });
    let response = fixture
        .app
        .oneshot(post_public_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// GET /device/public_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_public_keys_returns_all() {
    let (priv_jwk, kid, _sk, client, enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let response = fixture
        .app
        .oneshot(get_public_key_request(&token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["keys"].as_array().unwrap().len(), 2);
    assert_eq!(json["default_kid"].as_str().unwrap(), enc_kid);
}

// ---------------------------------------------------------------------------
// DELETE /device/public_key/{kid} tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_public_key_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // Patch pub_json to include "use":"sig" and "alg":"ES256" (generate_signing_key_pair omits them)
    let mut pub_val: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
    pub_val["use"] = json!("sig");
    pub_val["alg"] = json!("ES256");
    let pub_json_patched = serde_json::to_string(&pub_val).unwrap();
    // Two sig keys + one enc key
    let keys = format!(
        "[{pub_json_patched},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-2\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-del", "tok-del", &keys, "enc-1");
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-del", "/device/public_key/sig-2");
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-2")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_public_key_last_sig_returns_409() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{kid}"),
    );
    let response = app
        .oneshot(
            Request::delete(format!("/device/public_key/{kid}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_last_enc_returns_409() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{enc_kid}"),
    );
    let response = app
        .oneshot(
            Request::delete(format!("/device/public_key/{enc_kid}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_not_found_returns_404() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key/nonexistent");
    let response = app
        .oneshot(
            Request::delete("/device/public_key/nonexistent")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_public_key_in_flight_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // Two sig keys + one enc key
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-flight\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-flight", "tok-flight", &keys, "enc-1");
    let mut repo = MockRepository::with_client(sk, client);
    repo.in_flight_kids = Mutex::new(vec!["sig-flight".to_owned()]);
    let state = make_test_app_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-flight",
        "/device/public_key/sig-flight",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-flight")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_auto_reassign_default_kid() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    // One sig key + two enc keys, default_kid = enc-del
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-del\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-keep\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-reassign", "tok-reassign", &keys, "enc-del");
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(Arc::clone(&repo) as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-reassign",
        "/device/public_key/enc-del",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/enc-del")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // FINDING-10: verify default_kid was reassigned to the remaining enc key
    let c = repo
        .get_client_by_id("fid-reassign")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.default_kid, "enc-keep");
}

// ---------------------------------------------------------------------------
// Edge-case tests (FINDING-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_public_key_default_kid_referencing_sig_key_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    // default_kid points to the sig key (kid), which is not an enc key
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": kid
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_default_kid_nonexistent_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": "enc-new", "x": X_COORD, "y": Y_COORD }],
        "default_kid": "nonexistent-kid"
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_public_key_no_default_kid_reassign_when_not_affected() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let mut pub_val: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
    pub_val["use"] = json!("sig");
    pub_val["alg"] = json!("ES256");
    let pub_json_patched = serde_json::to_string(&pub_val).unwrap();
    // Two sig keys + one enc key, default_kid = enc-1
    let keys = format!(
        "[{pub_json_patched},{{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"sig-extra\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-noreassign", "tok-noreassign", &keys, "enc-1");
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(Arc::clone(&repo) as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    // Delete a sig key that is NOT the default_kid
    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-noreassign",
        "/device/public_key/sig-extra",
    );
    let response = app
        .oneshot(
            Request::delete("/device/public_key/sig-extra")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify default_kid is unchanged
    let c = repo
        .get_client_by_id("fid-noreassign")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.default_kid, "enc-1");
}

#[tokio::test]
async fn add_public_key_duplicate_kid_rejected() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let repo = build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    // Try to add a key with the same kid as the existing enc key
    let body = json!({
        "keys": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "kid": enc_kid, "x": X_COORD, "y": Y_COORD }]
    });
    let response = app
        .oneshot(
            Request::post("/device/public_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
