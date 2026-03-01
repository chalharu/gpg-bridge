use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{DeviceClaims, PayloadType, generate_signing_key_pair, jwk_to_json, sign_jws};
use crate::test_support::{MockRepository, make_test_app_state};

use super::{
    SECRET, X_COORD, Y_COORD, build_test_router, make_client_row, make_device_assertion,
    make_signing_key_row, register_body,
};

#[tokio::test]
async fn register_device_success() {
    let (sk, _) = make_signing_key_row();
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_test_router(state);

    let body = register_body("fid-1", "token-1");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["device_jwt"].as_str().is_some());
}

#[tokio::test]
async fn register_device_fid_conflict() {
    let (sk, _) = make_signing_key_row();
    let client = make_client_row("fid-1", "old-token", "[]", "kid-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let body = register_body("fid-1", "token-1");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_token_conflict() {
    let (sk, _) = make_signing_key_row();
    let client = make_client_row("other-fid", "shared-token", "[]", "kid-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let body = register_body("fid-1", "shared-token");
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_device_missing_sig_keys() {
    let (sk, _) = make_signing_key_row();
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_test_router(state);

    let body = json!({
        "device_token": "t",
        "firebase_installation_id": "fid-1",
        "public_key": { "keys": { "sig": [], "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": X_COORD, "y": Y_COORD }] } }
    });
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_device_invalid_sig_key_alg() {
    let (sk, _) = make_signing_key_row();
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_test_router(state);

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
    let response = app
        .oneshot(
            Request::post("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// PATCH /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_device_token_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "old-token", &keys, "enc-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-token" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "tok", &keys, "enc-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": "enc-1" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_default_kid_not_found_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "tok", &keys, "enc-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "default_kid": "nonexistent-kid" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
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
async fn update_device_both_fields_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-1", "old-tok", &keys, "enc-1");
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-1", "/device");
    let body = json!({ "device_token": "new-tok", "default_kid": "enc-1" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_device_empty_body_returns_400() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let client = make_client_row("fid-2", "tok", &format!("[{pub_json}]"), &kid);
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-2", "/device");
    let body = json!({});
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/device")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// DELETE /device tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_device_success() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let client = make_client_row("fid-3", "tok", &format!("[{pub_json}]"), &kid);
    let state = make_test_app_state(MockRepository::with_client(sk, client));
    let app = build_test_router(state);

    let token = make_device_assertion(&priv_jwk, &kid, "fid-3", "/device");
    let response = app
        .oneshot(
            Request::delete("/device")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// POST /device/refresh tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_device_jwt_success() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _server_pub) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let keys = format!("[{client_pub_json}]");
    let client = make_client_row("fid-4", "tok", &keys, &client_kid);
    let repo = MockRepository::with_client(sk.clone(), client);
    let state = make_test_app_state(repo);

    // Issue a device_jwt using the server signing key.
    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "fid-4".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_device_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-4", "/device/refresh");
    let body = json!({ "device_jwt": old_device_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
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
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let client = make_client_row("fid-5", "tok", &format!("[{client_pub_json}]"), &client_kid);
    let repo = MockRepository::with_client(sk.clone(), client);
    let state = make_test_app_state(repo);

    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "wrong-fid".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-5", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_device_jwt_expired_issued_at_returns_401() {
    let (client_priv, client_pub, client_kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let client_pub_json = jwk_to_json(&client_pub).unwrap();
    let mut client = make_client_row("fid-6", "tok", &format!("[{client_pub_json}]"), &client_kid);
    // Set device_jwt_issued_at far in the past so validity check fails.
    client.device_jwt_issued_at = "2020-01-01T00:00:00+00:00".to_owned();
    let repo = MockRepository::with_client(sk.clone(), client);
    let state = make_test_app_state(repo);

    let server_priv_json = crate::jwt::decrypt_private_key(&sk.private_key, SECRET).unwrap();
    let server_priv = crate::jwt::jwk_from_json(&server_priv_json).unwrap();
    let device_claims = DeviceClaims {
        sub: "fid-6".into(),
        payload_type: PayloadType::Device,
        exp: 1_900_000_000,
    };
    let old_jwt = sign_jws(&device_claims, &server_priv, &sk.kid).unwrap();

    let app = build_test_router(state);
    let assertion = make_device_assertion(&client_priv, &client_kid, "fid-6", "/device/refresh");
    let body = json!({ "device_jwt": old_jwt });
    let response = app
        .oneshot(
            Request::post("/device/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
