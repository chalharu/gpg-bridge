use std::sync::Arc;

use axum::body;
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use crate::repository::ClientRepository;
use crate::test_support::{MockRepository, make_test_app_state, make_test_app_state_arc};

use super::{
    DeviceAppFixture, assert_device_request_status_keeps_client_state,
    build_sqlite_device_app_with_client, build_test_router, delete_device_item_request,
    get_device_request, make_device_assertion, make_device_key_test_setup, make_gpg_client_row,
    make_gpg_test_setup, post_device_json_request,
};

fn assert_gpg_device_state_unchanged(
    before: &crate::repository::ClientRow,
    after: &crate::repository::ClientRow,
    case_name: &str,
) {
    assert_eq!(after.gpg_keys, before.gpg_keys, "case failed: {case_name}");
    assert_eq!(
        after.public_keys, before.public_keys,
        "case failed: {case_name}"
    );
    assert_eq!(
        after.default_kid, before.default_kid,
        "case failed: {case_name}"
    );
}

struct DeleteFailureCase<'a> {
    name: &'a str,
    client_id: &'a str,
    keygrip: &'a str,
    expected_status: StatusCode,
}

async fn assert_delete_gpg_key_failure_keeps_db_state(
    app: &axum::Router,
    repo: &(impl ClientRepository + ?Sized),
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    case: DeleteFailureCase<'_>,
) {
    let token = make_device_assertion(
        priv_jwk,
        kid,
        case.client_id,
        &format!("/device/gpg_key/{}", case.keygrip),
    );

    assert_device_request_status_keeps_client_state(
        case.name,
        app,
        repo,
        case.client_id,
        delete_device_item_request("/device/gpg_key", case.keygrip, &token),
        case.expected_status,
        assert_gpg_device_state_unchanged,
    )
    .await;
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
        .oneshot(post_device_json_request("/device/gpg_key", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn add_gpg_key_bad_request_cases() {
    struct Case {
        name: &'static str,
        build_body: fn() -> serde_json::Value,
    }

    let cases = [
        Case {
            name: "empty keys",
            build_body: || json!({ "gpg_keys": [] }),
        },
        Case {
            name: "invalid keygrip",
            build_body: || {
                json!({
                    "gpg_keys": [{
                        "keygrip": "TOOSHORT",
                        "key_id": "0xABCD",
                        "public_key": { "kty": "EC" }
                    }]
                })
            },
        },
        Case {
            name: "invalid key id",
            build_body: || {
                json!({
                    "gpg_keys": [{
                        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": "not-hex!",
                        "public_key": { "kty": "EC" }
                    }]
                })
            },
        },
        Case {
            name: "empty public key",
            build_body: || {
                json!({
                    "gpg_keys": [{
                        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": "0xABCD",
                        "public_key": {}
                    }]
                })
            },
        },
        Case {
            name: "non object public key",
            build_body: || {
                json!({
                    "gpg_keys": [{
                        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": "0xABCD",
                        "public_key": "not-an-object"
                    }]
                })
            },
        },
        Case {
            name: "key id too long",
            build_body: || {
                let long_key_id = format!("0x{}", "A".repeat(41));
                json!({
                    "gpg_keys": [{
                        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": long_key_id,
                        "public_key": { "kty": "EC" }
                    }]
                })
            },
        },
    ];

    for case in cases {
        let (priv_jwk, kid, _sk, client) = make_gpg_test_setup();
        let fixture = DeviceAppFixture::with_client(&client).await;
        let body = (case.build_body)();

        let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");

        assert_device_request_status_keeps_client_state(
            case.name,
            &fixture.app,
            fixture.repo.as_ref(),
            "fid-gpg",
            post_device_json_request("/device/gpg_key", &token, &body),
            StatusCode::BAD_REQUEST,
            assert_gpg_device_state_unchanged,
        )
        .await;
    }
}

#[tokio::test]
async fn add_gpg_key_upsert_overwrites_existing() {
    let (priv_jwk, kid, _sk, enc_kid, keys) = make_device_key_test_setup();
    let existing_gpg = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xAABB",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);
    let client = make_gpg_client_row("fid-upsert", &keys, &enc_kid, &existing_gpg.to_string());
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
        .oneshot(post_device_json_request("/device/gpg_key", &token, &body))
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
    let (priv_jwk, kid, _sk, enc_kid, keys) = make_device_key_test_setup();
    let gpg = json!([{
        "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "key_id": "0xEF",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-list", &keys, &enc_kid, &gpg.to_string());
    let fixture = DeviceAppFixture::with_client(&client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-list", "/device/gpg_key");
    let response = fixture
        .app
        .oneshot(get_device_request("/device/gpg_key", &token))
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
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-gpg", "/device/gpg_key");
    let response = app
        .oneshot(get_device_request("/device/gpg_key", &token))
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
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-gpg", &keys, &enc_kid, &gpg.to_string());
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(
        &priv_jwk,
        &kid,
        "fid-del-gpg",
        "/device/gpg_key/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    );
    let response = app
        .oneshot(delete_device_item_request(
            "/device/gpg_key",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_gpg_key_failure_cases() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-fail", &keys, &enc_kid, &gpg.to_string());
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let cases = [
        DeleteFailureCase {
            name: "not found",
            client_id: "fid-del-fail",
            keygrip: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
            expected_status: StatusCode::NOT_FOUND,
        },
        DeleteFailureCase {
            name: "invalid keygrip format",
            client_id: "fid-del-fail",
            keygrip: "invalid-format",
            expected_status: StatusCode::BAD_REQUEST,
        },
    ];

    for case in cases {
        assert_delete_gpg_key_failure_keeps_db_state(&app, repo.as_ref(), &priv_jwk, &kid, case)
            .await;
    }
}

#[tokio::test]
async fn add_gpg_key_multiple_keys_success() {
    let (priv_jwk, kid, sk, client) = make_gpg_test_setup();
    let (repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

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
        .oneshot(post_device_json_request("/device/gpg_key", &token, &body))
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
        .oneshot(post_device_json_request("/device/gpg_key", &token, &body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_gpg_key_concurrent_modification_conflict() {
    let (priv_jwk, kid, sk, enc_kid, keys) = make_device_key_test_setup();
    let gpg = json!([{
        "keygrip": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "key_id": "0xDEAD",
        "public_key": { "kty": "EC" }
    }]);
    let client = make_gpg_client_row("fid-del-conflict", &keys, &enc_kid, &gpg.to_string());
    let mut repo = MockRepository::with_client(sk, client);
    repo.force_gpg_update_conflict = true;
    let repo = Arc::new(repo);
    let state =
        make_test_app_state_arc(repo.clone() as Arc<dyn crate::repository::SignatureRepository>);
    let app = build_test_router(state);

    assert_delete_gpg_key_failure_keeps_db_state(
        &app,
        repo.as_ref(),
        &priv_jwk,
        &kid,
        DeleteFailureCase {
            name: "concurrent modification conflict",
            client_id: "fid-del-conflict",
            keygrip: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            expected_status: StatusCode::CONFLICT,
        },
    )
    .await;
}
