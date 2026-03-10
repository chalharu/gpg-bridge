use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::ClientRepository;

use super::{
    X_COORD, Y_COORD, authed_json_request, build_sqlite_device_app,
    build_sqlite_device_app_with_client, json_request, make_client_row, make_device_assertion,
    make_signing_key_row, register_body,
};

fn post_device_request(body: &serde_json::Value) -> Request<Body> {
    json_request(Method::POST, "/device", body)
}

fn patch_device_request(token: &str, body: &serde_json::Value) -> Request<Body> {
    authed_json_request(Method::PATCH, "/device", token, body)
}

// ---------------------------------------------------------------------------
// register: verify stored client row fields  (kills build_client_row mutations)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_device_stores_correct_client_row() {
    let (sk, _) = make_signing_key_row();
    let (repo, app) = build_sqlite_device_app(&sk).await;

    let body = register_body("fid-row", "tok-row");
    let response = app.oneshot(post_device_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let c = repo.get_client_by_id("fid-row").await.unwrap().unwrap();
    assert_eq!(c.client_id, "fid-row");
    assert_eq!(c.device_token, "tok-row");
    assert!(!c.public_keys.is_empty());
    assert!(!c.default_kid.is_empty());
    assert!(!c.created_at.is_empty());
    assert!(!c.updated_at.is_empty());
    assert!(!c.device_jwt_issued_at.is_empty());
    assert_eq!(c.gpg_keys, "[]");
}

// ---------------------------------------------------------------------------
// register: verify JWT content (kills issue_device_jwt mutations)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_device_jwt_has_correct_sub_and_future_exp() {
    let (sk, pub_jwk) = make_signing_key_row();
    let (_repo, app) = build_sqlite_device_app(&sk).await;

    let before = chrono::Utc::now().timestamp();
    let body = register_body("fid-jwt", "tok-jwt");
    let response = app.oneshot(post_device_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let jwt_str = json["device_jwt"].as_str().unwrap();

    // Decode and verify the JWT payload.
    let verifier = josekit::jws::ES256.verifier_from_jwk(&pub_jwk).unwrap();
    let (payload, _header) = josekit::jwt::decode_with_verifier(jwt_str, &verifier).unwrap();

    let sub = payload.subject().unwrap();
    assert_eq!(
        sub, "fid-jwt",
        "JWT sub must match firebase_installation_id"
    );

    let exp_systime = payload.expires_at().unwrap();
    let exp = exp_systime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // exp must be at least 1 year from before (31_536_000 seconds)
    assert!(
        exp >= before + 31_536_000,
        "JWT exp must be ~1 year in the future, got {exp} vs now {before}"
    );
    // exp must use addition, not subtraction (kills `+` → `-` mutation)
    assert!(exp > before, "JWT exp must be in the future (not negative)");
}

// ---------------------------------------------------------------------------
// register: default_kid selection (kills resolve_default_kid mutations)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_device_uses_first_enc_kid_when_none_specified() {
    let (sk, _) = make_signing_key_row();
    let (repo, app) = build_sqlite_device_app(&sk).await;

    // Body without explicit default_kid — should use the enc key's kid
    let body = json!({
        "device_token": "tok-dk",
        "firebase_installation_id": "fid-dk",
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256",
                           "x": X_COORD, "y": Y_COORD }],
                "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256",
                           "alg": "ECDH-ES+A256KW", "kid": "my-enc-kid",
                           "x": X_COORD, "y": Y_COORD }]
            }
        }
    });
    let response = app.oneshot(post_device_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let c = repo.get_client_by_id("fid-dk").await.unwrap().unwrap();
    assert_eq!(c.default_kid, "my-enc-kid");
}

#[tokio::test]
async fn register_device_uses_explicit_default_kid() {
    let (sk, _) = make_signing_key_row();
    let (repo, app) = build_sqlite_device_app(&sk).await;

    let body = json!({
        "device_token": "tok-ek",
        "firebase_installation_id": "fid-ek",
        "default_kid": "chosen-kid",
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256",
                           "x": X_COORD, "y": Y_COORD }],
                "enc": [
                    { "kty": "EC", "use": "enc", "crv": "P-256",
                      "alg": "ECDH-ES+A256KW", "kid": "other-kid",
                      "x": X_COORD, "y": Y_COORD },
                    { "kty": "EC", "use": "enc", "crv": "P-256",
                      "alg": "ECDH-ES+A256KW", "kid": "chosen-kid",
                      "x": X_COORD, "y": Y_COORD }
                ]
            }
        }
    });
    let response = app.oneshot(post_device_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let c = repo.get_client_by_id("fid-ek").await.unwrap().unwrap();
    assert_eq!(c.default_kid, "chosen-kid");
}

#[tokio::test]
async fn register_device_invalid_default_kid_returns_400() {
    let (sk, _) = make_signing_key_row();
    let (_repo, app) = build_sqlite_device_app(&sk).await;

    let body = json!({
        "device_token": "tok-bad",
        "firebase_installation_id": "fid-bad",
        "default_kid": "nonexistent-kid",
        "public_key": {
            "keys": {
                "sig": [{ "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256",
                           "x": X_COORD, "y": Y_COORD }],
                "enc": [{ "kty": "EC", "use": "enc", "crv": "P-256",
                           "alg": "ECDH-ES+A256KW", "kid": "enc-kid",
                           "x": X_COORD, "y": Y_COORD }]
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
// register: verify public_keys JSON (kills build_public_keys_json mutations)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_device_public_keys_contains_all_keys() {
    let (sk, _) = make_signing_key_row();
    let (repo, app) = build_sqlite_device_app(&sk).await;

    let body = register_body("fid-pk", "tok-pk");
    let response = app.oneshot(post_device_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let c = repo.get_client_by_id("fid-pk").await.unwrap().unwrap();
    let stored_keys: Vec<serde_json::Value> = serde_json::from_str(&c.public_keys).unwrap();
    // register_body provides 1 sig + 1 enc = 2 total
    assert_eq!(stored_keys.len(), 2);
}

// ---------------------------------------------------------------------------
// PATCH /device: only device_token set (kills && → || mutation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_device_only_token_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-ot", "old-tok", &keys, "enc-1");
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-ot", "/device");
    let body = json!({ "device_token": "new-tok" });
    let response = app
        .oneshot(patch_device_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "sending only device_token must succeed (not 400)"
    );
}

#[tokio::test]
async fn update_device_only_default_kid_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (sk, _) = make_signing_key_row();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let keys = format!(
        "[{pub_json},{{\"kty\":\"EC\",\"use\":\"enc\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"kid\":\"enc-1\",\"x\":\"{X_COORD}\",\"y\":\"{Y_COORD}\"}}]"
    );
    let client = make_client_row("fid-ok", "tok-ok", &keys, "enc-1");
    let (_repo, app) = build_sqlite_device_app_with_client(&sk, &client).await;

    let token = make_device_assertion(&priv_jwk, &kid, "fid-ok", "/device");
    let body = json!({ "default_kid": "enc-1" });
    let response = app
        .oneshot(patch_device_request(&token, &body))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "sending only default_kid must succeed (not 400)"
    );
}
