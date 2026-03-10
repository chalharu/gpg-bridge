use std::sync::{Arc, Mutex};

use axum::body;
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::{ClientRepository, SignatureRepository};
use crate::test_support::{MockRepository, make_test_app_state_arc};

use super::{
    DeviceAppFixture, assert_device_request_status_keeps_client_state,
    build_sqlite_device_app_with_client, build_test_router, delete_device_item_request,
    ec_public_key_json, ec_public_key_value, get_device_request, make_client_row,
    make_device_assertion, make_pk_test_setup, make_signing_key_row, post_device_json_request,
    public_keys_json, signing_public_key_json,
};

async fn post_public_keys_success(
    fixture: &DeviceAppFixture,
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    body: &serde_json::Value,
) -> (Vec<serde_json::Value>, String) {
    let token = make_device_assertion(priv_jwk, kid, "fid-pk", "/device/public_key");
    let response = fixture
        .app
        .clone()
        .oneshot(post_device_json_request("/device/public_key", &token, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let client = fixture
        .repo
        .get_client_by_id("fid-pk")
        .await
        .unwrap()
        .unwrap();
    let keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys).unwrap();

    (keys, client.default_kid)
}

fn assert_public_key_state_unchanged(
    before: &crate::repository::ClientRow,
    after: &crate::repository::ClientRow,
    case_name: &str,
) {
    assert_eq!(
        after.public_keys, before.public_keys,
        "case failed: {case_name}"
    );
    assert_eq!(
        after.default_kid, before.default_kid,
        "case failed: {case_name}"
    );
}

fn has_public_key_kid(keys: &[serde_json::Value], kid: &str) -> bool {
    keys.iter().any(|key| key["kid"].as_str() == Some(kid))
}

fn has_public_key(keys: &[serde_json::Value], key_use: &str, alg: &str, kid: &str) -> bool {
    keys.iter().any(|key| {
        key["use"].as_str() == Some(key_use)
            && key["alg"].as_str() == Some(alg)
            && key["kid"].as_str() == Some(kid)
    })
}

async fn stored_public_keys(
    repo: &(impl ClientRepository + ?Sized),
    client_id: &str,
) -> (Vec<serde_json::Value>, String) {
    let client = repo.get_client_by_id(client_id).await.unwrap().unwrap();
    let keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys).unwrap();
    (keys, client.default_kid)
}

struct DeleteFailureCase<'a> {
    name: &'a str,
    auth_kid: &'a str,
    client_id: &'a str,
    delete_kid: &'a str,
    expected_status: StatusCode,
}

async fn assert_delete_public_key_failure_keeps_db_state(
    app: &axum::Router,
    repo: &(impl ClientRepository + ?Sized),
    priv_jwk: &josekit::jwk::Jwk,
    case: DeleteFailureCase<'_>,
) {
    let token = make_device_assertion(
        priv_jwk,
        case.auth_kid,
        case.client_id,
        &format!("/device/public_key/{}", case.delete_kid),
    );

    assert_device_request_status_keeps_client_state(
        case.name,
        app,
        repo,
        case.client_id,
        delete_device_item_request("/device/public_key", case.delete_kid, &token),
        case.expected_status,
        assert_public_key_state_unchanged,
    )
    .await;
}

#[tokio::test]
async fn add_public_key_success_cases() {
    struct Case {
        name: &'static str,
        body: serde_json::Value,
        expected_use: &'static str,
        expected_alg: &'static str,
        expected_kid: Option<&'static str>,
        expected_default_kid: Option<&'static str>,
    }

    let cases = [
        Case {
            name: "sig key",
            body: json!({
                "keys": [ec_public_key_value("sig", "ES256", None)]
            }),
            expected_use: "sig",
            expected_alg: "ES256",
            expected_kid: None,
            expected_default_kid: None,
        },
        Case {
            name: "enc key",
            body: json!({
                "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", None)]
            }),
            expected_use: "enc",
            expected_alg: "ECDH-ES+A256KW",
            expected_kid: None,
            expected_default_kid: None,
        },
        Case {
            name: "enc key with default_kid change",
            body: json!({
                "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
                "default_kid": "enc-new"
            }),
            expected_use: "enc",
            expected_alg: "ECDH-ES+A256KW",
            expected_kid: Some("enc-new"),
            expected_default_kid: Some("enc-new"),
        },
    ];

    for case in cases {
        let (priv_jwk, kid, _sk, client, enc_kid, _keys) = make_pk_test_setup();
        let initial_keys: Vec<serde_json::Value> =
            serde_json::from_str(&client.public_keys).unwrap();
        let fixture = DeviceAppFixture::with_client(&client).await;
        let (keys, default_kid) =
            post_public_keys_success(&fixture, &priv_jwk, &kid, &case.body).await;

        assert_eq!(
            keys.len(),
            initial_keys.len() + 1,
            "case failed: {}",
            case.name
        );
        assert!(
            keys.iter().any(|key| {
                key["use"].as_str() == Some(case.expected_use)
                    && key["alg"].as_str() == Some(case.expected_alg)
                    && key["x"].as_str().is_some()
                    && key["y"].as_str().is_some()
                    && case
                        .expected_kid
                        .is_none_or(|expected_kid| key["kid"].as_str() == Some(expected_kid))
            }),
            "case failed: {}",
            case.name
        );
        assert_eq!(
            default_kid,
            case.expected_default_kid.unwrap_or(enc_kid.as_str()),
            "case failed: {}",
            case.name
        );
    }
}

#[tokio::test]
async fn add_public_key_bad_request_cases() {
    struct Case {
        name: &'static str,
        build_body: fn(&str, &str) -> serde_json::Value,
    }

    let cases = [
        Case {
            name: "invalid key",
            build_body: |_, _| {
                json!({
                    "keys": [ec_public_key_value("sig", "RS256", None)]
                })
            },
        },
        Case {
            name: "empty keys",
            build_body: |_, _| json!({ "keys": [] }),
        },
        Case {
            name: "unsupported use",
            build_body: |_, _| {
                json!({
                    "keys": [ec_public_key_value("other", "ES256", None)]
                })
            },
        },
        Case {
            name: "default_kid referencing sig key",
            build_body: |kid, _| {
                json!({
                    "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
                    "default_kid": kid
                })
            },
        },
        Case {
            name: "default_kid nonexistent",
            build_body: |_, _| {
                json!({
                    "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some("enc-new"))],
                    "default_kid": "nonexistent-kid"
                })
            },
        },
        Case {
            name: "duplicate kid",
            build_body: |_, enc_kid| {
                json!({
                    "keys": [ec_public_key_value("enc", "ECDH-ES+A256KW", Some(enc_kid))]
                })
            },
        },
        Case {
            name: "cross-type duplicate kid",
            build_body: |_, enc_kid| {
                json!({
                    "keys": [ec_public_key_value("sig", "ES256", Some(enc_kid))]
                })
            },
        },
    ];

    for case in cases {
        let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
        let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;
        let body = (case.build_body)(&kid, &enc_kid);

        let token = make_device_assertion(&priv_jwk, &kid, "fid-pk", "/device/public_key");

        assert_device_request_status_keeps_client_state(
            case.name,
            &app,
            repo.as_ref(),
            "fid-pk",
            post_device_json_request("/device/public_key", &token, &body),
            StatusCode::BAD_REQUEST,
            assert_public_key_state_unchanged,
        )
        .await;
    }
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
    assert!(has_public_key(keys, "enc", "ECDH-ES+A256KW", &enc_kid));
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
async fn delete_public_key_failure_cases() {
    struct Case {
        name: &'static str,
        delete_kid: &'static str,
        expected_status: StatusCode,
    }

    let cases = [
        Case {
            name: "last sig",
            delete_kid: "__auth_kid__",
            expected_status: StatusCode::CONFLICT,
        },
        Case {
            name: "last enc",
            delete_kid: "__enc_kid__",
            expected_status: StatusCode::CONFLICT,
        },
        Case {
            name: "not found",
            delete_kid: "nonexistent",
            expected_status: StatusCode::NOT_FOUND,
        },
    ];

    for case in cases {
        let (priv_jwk, kid, sk, client, enc_kid, _keys) = make_pk_test_setup();
        let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;
        let delete_kid = match case.delete_kid {
            "__auth_kid__" => kid.as_str(),
            "__enc_kid__" => enc_kid.as_str(),
            other => other,
        };

        assert_delete_public_key_failure_keeps_db_state(
            &app,
            repo.as_ref(),
            &priv_jwk,
            DeleteFailureCase {
                name: case.name,
                auth_kid: &kid,
                client_id: "fid-pk",
                delete_kid,
                expected_status: case.expected_status,
            },
        )
        .await;
    }
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
    let repo = Arc::new(repo);
    let state = make_test_app_state_arc(repo.clone() as Arc<dyn SignatureRepository>);
    let app = build_test_router(state);

    assert_delete_public_key_failure_keeps_db_state(
        &app,
        repo.as_ref(),
        &priv_jwk,
        DeleteFailureCase {
            name: "in flight",
            auth_kid: &kid,
            client_id: "fid-flight",
            delete_kid: "sig-flight",
            expected_status: StatusCode::CONFLICT,
        },
    )
    .await;
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
    let (keys, default_kid) = stored_public_keys(repo.as_ref(), "fid-reassign").await;
    assert!(!has_public_key_kid(&keys, "enc-del"));
    assert!(has_public_key_kid(&keys, "enc-keep"));
    assert_eq!(default_kid, "enc-keep");
}

// ---------------------------------------------------------------------------
// Edge-case tests (FINDING-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_public_key_default_kid_existing_enc_accepted_for_new_sig_key() {
    let (priv_jwk, kid, _sk, client, enc_kid, _keys) = make_pk_test_setup();
    let fixture = DeviceAppFixture::with_client(&client).await;

    let body = json!({
        "keys": [ec_public_key_value("sig", "ES256", Some("sig-new"))],
        "default_kid": enc_kid
    });
    let (_keys, _default_kid) = post_public_keys_success(&fixture, &priv_jwk, &kid, &body).await;

    let c = fixture
        .repo
        .get_client_by_id("fid-pk")
        .await
        .unwrap()
        .unwrap();
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
