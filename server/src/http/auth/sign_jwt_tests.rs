use super::*;
use crate::jwt::{generate_signing_key_pair, sign_jws};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceExt;

use crate::test_support::{MockRepository, make_signing_key_row, make_test_app_state};

async fn handler(_auth: SignJwtAuth) -> Json<String> {
    Json("ok".into())
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/sign-result", get(handler))
        .with_state(state)
}

fn make_sign_jwt(
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    request_id: &str,
    client_id: &str,
) -> String {
    let claims = SignClaims {
        sub: request_id.into(),
        client_id: client_id.into(),
        payload_type: PayloadType::Sign,
        exp: 1_900_000_000,
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

// ---- Tests ----

#[tokio::test]
async fn valid_sign_jwt_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let response = app
        .oneshot(
            Request::get("/sign-result")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_auth_returns_401() {
    let state = make_test_app_state(MockRepository::default());
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/sign-result").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_key_returns_401() {
    let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (_other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &other_pub, &other_kid);
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let response = app
        .oneshot(
            Request::get("/sign-result")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_sign_jwt_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_app(state);

    let claims = SignClaims {
        sub: "req-1".into(),
        client_id: "client-1".into(),
        payload_type: PayloadType::Sign,
        exp: 1_000_000_000, // past
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    let response = app
        .oneshot(
            Request::get("/sign-result")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_signing_key_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let mut sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    sk.expires_at = "2020-01-01T00:00:00Z".into(); // expired key
    let state = make_test_app_state(MockRepository::new(sk));
    let app = build_app(state);

    let token = make_sign_jwt(&priv_jwk, &kid, "req-1", "client-1");
    let response = app
        .oneshot(
            Request::get("/sign-result")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
