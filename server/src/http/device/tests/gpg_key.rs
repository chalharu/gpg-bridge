use std::sync::Arc;

use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::{ClientRepository, SignatureRepository, SigningKeyRepository};
use crate::test_support::{MockRepository, make_test_app_state, make_test_app_state_arc};

use super::{
    DeviceAppFixture, X_COORD, Y_COORD, authed_json_request, authed_request, build_test_router,
    build_test_sqlite_repo, make_device_assertion, make_gpg_client_row, make_gpg_test_setup,
    make_signing_key_row,
};

fn post_gpg_key_request(token: &str, body: &serde_json::Value) -> Request<Body> {
    authed_json_request(Method::POST, "/device/gpg_key", token, body)
}

fn get_gpg_key_request(token: &str) -> Request<Body> {
    authed_request(Method::GET, "/device/gpg_key", token)
}

#[tokio::test]
async fn add_gpg_key_success() {
    let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD1234EF567890",
            "public_key": { "kty": "EC", "crv": "P-256", "x": "abc", "y": "def" }
        }]
    });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_gpg_key_empty_rejected() {
    let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({ "gpg_keys": [] });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_invalid_keygrip_rejected() {
    let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "TOOSHORT",
            "key_id": "0xABCD",
            "public_key": { "kty": "EC" }
        }]
    });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_invalid_key_id_rejected() {
    let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "not-hex!",
            "public_key": { "kty": "EC" }
        }]
    });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_empty_public_key_rejected() {
    let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD",
            "public_key": {}
        }]
    });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_gpg_key_upsert_overwrites_existing() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (_sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let existing_gpg = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xAABB",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);
    let client = make_gpg_client_row("fid-upsert", &keys, "enc-1", &existing_gpg.to_string());
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-upsert", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xCCDD",
            "public_key": { "kty": "EC", "crv": "P-384" }
        }]
    });
    let response = fixture
        .app
        .oneshot(post_gpg_key_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = fixture
        .repo
        .get_client_by_id("fid-upsert")
        .await
        .unwrap()
        .unwrap();
    let gpg_keys: Vec<serde_json::Value> = serde_json::from_str(&c.gpg_keys).unwrap();
    assert_eq!(gpg_keys.len(), 1);
    assert_eq!(gpg_keys[0]["key_id"], "0xCCDD");
}

// ---------------------------------------------------------------------------
// GET /device/gpg_key tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_gpg_keys_returns_registered() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (_sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "key_id": "0xEF",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-list", &keys, "enc-1", &gpg.to_string());
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-list", "/device/gpg_key");
    let response = fixture
        .app
        .oneshot(get_gpg_key_request(&token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["gpg_keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn list_gpg_keys_empty() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> = build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let response = app
        .oneshot(
            Request::get("/device/gpg_key")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["gpg_keys"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// DELETE /device/gpg_key/{keygrip} tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_gpg_key_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-gpg", &keys, "enc-1", &gpg.to_string());
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-del-gpg",
        "/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_gpg_key_not_found() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-gpg",
        "/device/gpg_key/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn add_gpg_key_multiple_keys_success() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(Arc::clone(&repo) as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [
            {
                "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id": "0xABCD1234",
                "public_key": { "kty": "EC", "crv": "P-256" }
            },
            {
                "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "key_id": "0xEF567890",
                "public_key": { "kty": "EC", "crv": "P-384" }
            }
        ]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = repo.get_client_by_id("fid-gpg").await.unwrap().unwrap();
    let gpg_keys: Vec<serde_json::Value> = serde_json::from_str(&c.gpg_keys).unwrap();
    assert_eq!(gpg_keys.len(), 2);
}

#[tokio::test]
async fn add_gpg_key_concurrent_modification_conflict() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let mut repo = MockRepository::with_client(sk, client);
    repo.force_gpg_update_conflict = true;
    let state = make_test_app_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD1234",
            "public_key": { "kty": "EC", "crv": "P-256" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn add_gpg_key_non_object_public_key_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "0xABCD",
            "public_key": "not-an-object"
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
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
async fn add_gpg_key_key_id_too_long_rejected() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo: Arc<crate::repository::SqliteRepository> =
        crate::test_support::build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    // "0x" + 41 hex chars = 43 chars total, exceeds maxLength:42
    let long_key_id = format!("0x{}", "A".repeat(41));
    let body = json!({
        "gpg_keys": [{
            "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": long_key_id,
            "public_key": { "kty": "EC" }
        }]
    });
    let response = app
        .oneshot(
            Request::post("/device/gpg_key")
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
async fn delete_gpg_key_concurrent_modification_conflict() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-conflict", &keys, "enc-1", &gpg.to_string());
    let mut repo = MockRepository::with_client(sk, client);
    repo.force_gpg_update_conflict = true;
    let state = make_test_app_state(repo);
    let app = build_test_router(state);

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-del-conflict",
        "/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_gpg_key_invalid_keygrip_format() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let repo = build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key/invalid-format");
    let response = app
        .oneshot(
            Request::delete("/device/gpg_key/invalid-format")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
