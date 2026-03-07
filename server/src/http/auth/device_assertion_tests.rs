use super::*;
use crate::jwt::{generate_signing_key_pair, jwk_to_json, sign_jws};
use crate::repository::ClientRow;
use crate::test_support::{MockRepository, make_test_app_state};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceExt;

// ---- Helpers ----

fn make_state(repo: MockRepository) -> AppState {
    make_test_app_state(repo)
}

fn repo_with_client(client: ClientRow) -> MockRepository {
    MockRepository {
        clients: std::sync::Mutex::new(vec![client]),
        ..Default::default()
    }
}

fn replay_repo() -> MockRepository {
    MockRepository {
        jti_accepted: false,
        ..Default::default()
    }
}

async fn handler(_auth: DeviceAssertionAuth) -> Json<String> {
    Json("ok".into())
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/sign", get(handler))
        .with_state(state)
}

fn make_valid_token(priv_jwk: &josekit::jwk::Jwk, kid: &str, aud: &str) -> String {
    let claims = DeviceAssertionClaims {
        iss: "fid-1".into(),
        sub: "fid-1".into(),
        aud: aud.into(),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

fn make_client_row(pub_jwk: &josekit::jwk::Jwk, kid: &str) -> ClientRow {
    let pub_json = jwk_to_json(pub_jwk).unwrap();
    ClientRow {
        client_id: "fid-1".into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: kid.into(),
        gpg_keys: "[]".into(),
    }
}

// ---- Tests ----

#[tokio::test]
async fn valid_device_assertion_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_client_row(&pub_jwk, &kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let state = make_state(replay_repo());
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/v1/sign").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_key_returns_401() {
    let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (_other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
    // Client has a different key than the one used to sign
    let client = make_client_row(&other_pub, &other_kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    // Token signed with `priv_jwk` but client has `other_pub`
    // The kid won't match, so we'll get "no public key found"
    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_not_found_returns_401() {
    let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let repo = MockRepository::default();
    let state = make_state(repo);
    let app = build_app(state);

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_aud_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_client_row(&pub_jwk, &kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    // Token has wrong audience
    let token = make_valid_token(&priv_jwk, &kid, "https://wrong.example.com/v1/sign");
    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_client_row(&pub_jwk, &kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    let claims = DeviceAssertionClaims {
        iss: "fid-1".into(),
        sub: "fid-1".into(),
        aud: "https://api.example.com/v1/sign".into(),
        exp: 1_000_000_000, // past
        iat: 1_000_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn iss_ne_sub_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_client_row(&pub_jwk, &kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    let claims = DeviceAssertionClaims {
        iss: "different-fid".into(),
        sub: "fid-1".into(),
        aud: "https://api.example.com/v1/sign".into(),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jti_replay_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_jwk).unwrap();
    let client = ClientRow {
        client_id: "fid-1".into(),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        device_token: "tok".into(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".into(),
        public_keys: format!("[{pub_json}]"),
        default_kid: kid.clone(),
        gpg_keys: "[]".into(),
    };
    let repo = MockRepository {
        clients: std::sync::Mutex::new(vec![client]),
        jti_accepted: false,
        ..Default::default()
    };
    let state = make_state(repo);
    let app = build_app(state);

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn exp_window_too_large_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_client_row(&pub_jwk, &kid);
    let state = make_state(repo_with_client(client));
    let app = build_app(state);

    // exp - iat = 120 > 60 → rejected
    let claims = DeviceAssertionClaims {
        iss: "fid-1".into(),
        sub: "fid-1".into(),
        aud: "https://api.example.com/v1/sign".into(),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 120,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    let response = app
        .oneshot(
            Request::get("/v1/sign")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
