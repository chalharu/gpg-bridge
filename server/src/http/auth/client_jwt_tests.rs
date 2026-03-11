use super::*;
use crate::jwt::{encrypt_jwe_direct, generate_signing_key_pair, sign_jws};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use tower::ServiceExt;

use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
    make_test_client_pairing_row,
};

async fn handler(_auth: ClientJwtAuth) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/tokens", post(handler))
        .with_state(state)
}

fn json_body(tokens: &[String]) -> Body {
    let body = serde_json::json!({ "client_jwts": tokens });
    Body::from(serde_json::to_vec(&body).unwrap())
}

// ---- Tests ----

#[tokio::test]
async fn valid_single_client_jwt_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository {
        signing_key: Some(sk),
        client_pairings_data: std::sync::Mutex::new(vec![make_test_client_pairing_row(
            "fid-1", "pair-1",
        )]),
        ..Default::default()
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_verification_failure_rejects_all() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository {
        signing_key: Some(sk),
        client_pairings_data: std::sync::Mutex::new(vec![make_test_client_pairing_row(
            "fid-1", "pair-1",
        )]),
        ..Default::default()
    };
    let app = build_app(make_test_app_state(repo));

    let valid_token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let bad_token = "invalid.jwt.token".to_owned();
    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[valid_token, bad_token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairing_not_found_filters_out() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    // No pairings in DB → all filtered out → 401
    let repo = MockRepository {
        signing_key: Some(sk),
        ..Default::default()
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_body_returns_401() {
    let repo = MockRepository::default();
    let app = build_app(make_test_app_state(repo));

    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn multiple_valid_tokens_returns_all() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository {
        signing_key: Some(sk),
        client_pairings_data: std::sync::Mutex::new(vec![
            make_test_client_pairing_row("fid-1", "pair-1"),
            make_test_client_pairing_row("fid-2", "pair-2"),
        ]),
        ..Default::default()
    };
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-2", "pair-2");
    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[t1, t2]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn expired_outer_jws_rejects_all() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository {
        signing_key: Some(sk),
        client_pairings_data: std::sync::Mutex::new(vec![make_test_client_pairing_row(
            "fid-1", "pair-1",
        )]),
        ..Default::default()
    };
    let app = build_app(make_test_app_state(repo));

    // Create token with expired outer JWS
    let inner_claims = ClientInnerClaims {
        sub: "fid-1".into(),
        pairing_id: "pair-1".into(),
    };
    let inner_bytes = serde_json::to_vec(&inner_claims).unwrap();
    let jwe = encrypt_jwe_direct(&inner_bytes, &pub_jwk).unwrap();
    let outer = ClientOuterClaims {
        payload_type: PayloadType::Client,
        client_jwe: jwe,
        exp: 1_000_000_000, // past
    };
    let token = sign_jws(&outer, &priv_jwk, &kid).unwrap();

    let response = app
        .oneshot(
            Request::post("/v1/tokens")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
