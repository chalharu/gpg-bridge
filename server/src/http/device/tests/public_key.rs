use std::sync::{Arc, Mutex};

use axum::body;
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::{ClientRepository, SignatureRepository, SigningKeyRepository};
use crate::test_support::{
    MockRepository, build_test_sqlite_repo, make_test_app_state, make_test_app_state_arc,
};

use super::{
    DeviceAppFixture, build_sqlite_device_app_with_client, build_test_router,
    delete_device_item_request, ec_public_key_json, ec_public_key_value, get_device_request,
    make_client_row, make_device_assertion, make_pk_test_setup, make_signing_key_row,
    post_device_json_request, public_keys_json, signing_public_key_json,
};

#[tokio::test]
async fn add_public_key_sig_success() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("sig", "ES256", None)]
    });
    let response = fixture
        .app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = fixture
        .repo
        .get_client_by_id("fid-pk")
        .await
        .unwrap()
        .unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(keys.iter().any(|key| {
        key["use"].as_str() == Some("sig")
            && key["alg"].as_str() == Some("ES256")
            && key["x"].as_str() == Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
            && key["y"].as_str() == Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
    }));
}

#[tokio::test]
async fn add_public_key_enc_success() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", None)]
    });
    let response = fixture
        .app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = fixture
        .repo
        .get_client_by_id("fid-pk")
        .await
        .unwrap()
        .unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(keys.iter().any(|key| {
        key["use"].as_str() == Some("enc")
            && key["alg"].as_str() == Some("ECDH-ES+A256KW")
            && key["x"].as_str() == Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
            && key["y"].as_str() == Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
    }));
}

#[tokio::test]
async fn add_public_key_with_default_kid_change() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
        "default_kid": "enc-new"
    });
    let response = fixture
        .app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = fixture
        .repo
        .get_client_by_id("fid-pk")
        .await
        .unwrap()
        .unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(keys.iter().any(|key| {
        key["use"].as_str() == Some("enc")
            && key["alg"].as_str() == Some("ECDH-ES+A256KW")
            && key["kid"].as_str() == Some("enc-new")
    }));
    assert_eq!(c.default_kid, "enc-new");
}

#[tokio::test]
async fn add_public_key_invalid_key_rejected() {
    let (priv_jwk, kid, _sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("sig", "RS256", None)]
    });
    let response = fixture
        .app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
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
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
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
        "keys": [ec_public_key_value("other", "ES256", None)]
    });
    let response = fixture
        .app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
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
        .oneshot(get_device_request("/device/public_key", &token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        keys.iter()
            .filter(|key| key["use"].as_str() == Some("sig"))
            .count(),
        1
    );
    assert_eq!(
        keys.iter()
            .filter(|key| key["use"].as_str() == Some("enc"))
            .count(),
        1
    );
    assert!(keys.iter().any(|key| {
        key["use"].as_str() == Some("enc")
            && key["alg"].as_str() == Some("ECDH-ES+A256KW")
            && key["kid"].as_str() == Some(&enc_kid)
    }));
    assert_eq!(json["default_kid"].as_str().unwrap(), enc_kid);
}

// ---------------------------------------------------------------------------
// DELETE /device/public_key/{kid} tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_public_key_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let keys = public_keys_json(&[
        signing_public_key_json(&pub_jwk),
        ec_public_key_json("sig", "ES256", "sig-2"),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-1"),
    ]);
    let client = make_client_row("fid-del", "tok-del", &keys, "enc-1");
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-del", "/device/public_key/sig-2");
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "sig-2",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = repo.get_client_by_id("fid-del").await.unwrap().unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(keys.iter().all(|key| key["kid"].as_str() != Some("sig-2")));
    assert!(keys.iter().any(|key| key["kid"].as_str() == Some("enc-1")));
    assert_eq!(c.default_kid, "enc-1");
}

#[tokio::test]
async fn delete_public_key_last_sig_returns_409() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{kid}"),
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            &kid,
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_last_enc_returns_409() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-pk",
        &format!("/device/public_key/{enc_kid}"),
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            &enc_kid,
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_not_found_returns_404() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key/nonexistent");
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "nonexistent",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_public_key_in_flight_returns_409() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let keys = public_keys_json(&[
        signing_public_key_json(&pub_jwk),
        ec_public_key_json("sig", "ES256", "sig-flight"),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-1"),
    ]);
    let client = make_client_row("fid-flight", "tok-flight", &keys, "enc-1");
    // This path needs MockRepository so the test can mark a kid as in-flight directly.
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
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "sig-flight",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_public_key_auto_reassign_default_kid() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let keys = public_keys_json(&[
        signing_public_key_json(&pub_jwk),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-del"),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-keep"),
    ]);
    let client = make_client_row("fid-reassign", "tok-reassign", &keys, "enc-del");
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-reassign",
        "/device/public_key/enc-del",
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "enc-del",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Reassignment picks the first remaining enc key in array order.
    let c = repo
        .get_client_by_id("fid-reassign")
        .await
        .unwrap()
        .unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(
        keys.iter()
            .all(|key| key["kid"].as_str() != Some("enc-del"))
    );
    assert!(
        keys.iter()
            .any(|key| key["kid"].as_str() == Some("enc-keep"))
    );
    assert_eq!(c.default_kid, "enc-keep");
}

// ---------------------------------------------------------------------------
// Edge-case tests (FINDING-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_public_key_default_kid_referencing_sig_key_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    // default_kid points to the sig key (kid), which is not an enc key
    let body = json!({
        "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
        "default_kid": kid
    });
    let response = app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_default_kid_nonexistent_rejected() {
    let (priv_jwk, kid, sk, client, _enc_kid, _keys) = make_pk_test_setup();
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
        "default_kid": "nonexistent-kid"
    });
    let response = app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_default_kid_existing_enc_accepted_for_new_sig_key() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("sig", "ES256", Some("sig-new"))],
        "default_kid": enc_kid
    });
    let response = app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = repo.get_client_by_id("fid-pk").await.unwrap().unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(keys.iter().any(|key| key["kid"].as_str() == Some(&kid)));
    assert!(
        keys.iter()
            .any(|key| key["kid"].as_str() == Some("sig-new"))
    );
    assert_eq!(c.default_kid, enc_kid);
}

#[tokio::test]
async fn delete_public_key_no_default_kid_reassign_when_not_affected() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let keys = public_keys_json(&[
        signing_public_key_json(&pub_jwk),
        ec_public_key_json("sig", "ES256", "sig-extra"),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-1"),
    ]);
    let client = make_client_row("fid-noreassign", "tok-noreassign", &keys, "enc-1");
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    // Delete a sig key that is NOT the default_kid
    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-noreassign",
        "/device/public_key/sig-extra",
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "sig-extra",
            &token,
        ))
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
async fn delete_non_default_enc_key_keeps_default_kid_when_other_enc_remains() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let keys = public_keys_json(&[
        signing_public_key_json(&pub_jwk),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-default"),
        ec_public_key_json("enc", "ECDH-ES+A256KW", "enc-other"),
    ]);
    let client = make_client_row(
        "fid-enc-keep-default",
        "tok-enc-keep-default",
        &keys,
        "enc-default",
    );
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-enc-keep-default",
        "/device/public_key/enc-other",
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/public_key",
            "enc-other",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let c = repo
        .get_client_by_id("fid-enc-keep-default")
        .await
        .unwrap()
        .unwrap();
    let keys: serde_json::Value = serde_json::from_str(&c.public_keys).unwrap();
    let keys = keys.as_array().unwrap();
    assert!(
        keys.iter()
            .all(|key| key["kid"].as_str() != Some("enc-other"))
    );
    assert!(
        keys.iter()
            .any(|key| key["kid"].as_str() == Some("enc-default"))
    );
    assert_eq!(c.default_kid, "enc-default");
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
        "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some(&enc_kid))]
    });
    let response = app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_public_key_cross_type_duplicate_kid_rejected() {
    let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
    let repo = build_test_sqlite_repo().await;
    repo.store_signing_key(&sk).await.unwrap();
    repo.create_client(&client).await.unwrap();
    let state = make_test_app_state_arc(repo as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");
    let body = json!({
        "keys": [ec_public_key_value("sig", "ES256", Some(&enc_kid))]
    });
    let response = app
        .oneshot(post_device_json_request(
            "/device/public_key",
            &token,
            &body,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
