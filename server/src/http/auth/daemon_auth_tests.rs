use super::*;
use crate::http::auth::test_support::{
    build_daemon_auth_app, daemon_auth_repo, get_sign_status, make_auth_state,
};
use crate::jwt::{generate_signing_key_pair, jwk_to_json, sign_jws};
use crate::repository::RequestRow;
use crate::test_support::make_signing_key_row;

// ---- Helpers ----

/// Create a valid daemon_auth_jws token:
/// 1. Sign a request_jwt with the server's key
/// 2. Sign the outer JWS with the daemon's key
fn make_daemon_token(
    server_priv: &josekit::jwk::Jwk,
    server_kid: &str,
    daemon_priv: &josekit::jwk::Jwk,
    daemon_kid: &str,
    request_id: &str,
    aud: &str,
) -> String {
    let request_claims = RequestClaims {
        sub: request_id.into(),
        payload_type: PayloadType::Request,
        exp: 1_900_000_000,
    };
    let request_jwt = sign_jws(&request_claims, server_priv, server_kid).unwrap();

    let outer_claims = DaemonAuthClaims {
        request_jwt,
        aud: aud.into(),
        iat: 1_900_000_000 - 30,
        exp: 1_900_000_000,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&outer_claims, daemon_priv, daemon_kid).unwrap()
}

// ---- Tests ----

#[tokio::test]
async fn valid_daemon_auth_succeeds() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/v1/sign",
    );

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let repo = daemon_auth_repo(None, None, true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    assert_eq!(
        get_sign_status(app, None).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_daemon_key_returns_401() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, _daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();
    let (_wrong_priv, wrong_pub, _wrong_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    // DB has wrong_pub as daemon key, but token is signed with daemon_priv
    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&wrong_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/v1/sign",
    );

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn request_not_found_returns_401() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, _daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let repo = daemon_auth_repo(Some(sk), None, true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/v1/sign",
    );

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_aud_returns_401() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://wrong.example.com/v1/sign", // wrong aud
    );

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jti_replay_returns_401() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), false);
    let app = build_daemon_auth_app(make_auth_state(repo));

    let token = make_daemon_token(
        &server_priv,
        &server_kid,
        &daemon_priv,
        &daemon_kid,
        "req-1",
        "https://api.example.com/v1/sign",
    );

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_outer_jws_returns_401() {
    let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    let sk = make_signing_key_row(&server_priv, &server_pub, &server_kid);
    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    // Create token with expired outer JWS
    let request_claims = RequestClaims {
        sub: "req-1".into(),
        payload_type: PayloadType::Request,
        exp: 1_900_000_000,
    };
    let request_jwt = sign_jws(&request_claims, &server_priv, &server_kid).unwrap();
    let outer = DaemonAuthClaims {
        request_jwt,
        aud: "https://api.example.com/v1/sign".into(),
        iat: 1_000_000_000 - 30,
        exp: 1_000_000_000, // past
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&outer, &daemon_priv, &daemon_kid).unwrap();

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn invalid_request_jwt_returns_401() {
    let (_server_priv, _server_pub, _server_kid) = generate_signing_key_pair().unwrap();
    let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();

    // Use a different server key for signing the request_jwt (wrong key)
    let (other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&other_priv, &other_pub, &other_kid);

    let request = RequestRow {
        request_id: "req-1".into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));

    // request_jwt signed with _server_priv but DB has other_pub
    let request_claims = RequestClaims {
        sub: "req-1".into(),
        payload_type: PayloadType::Request,
        exp: 1_900_000_000,
    };
    // Sign with _server_priv but extract_kid will return _server_kid,
    // which won't match other_kid in the DB.
    // So let's sign with other_priv but wrong payload type so it fails
    // Actually, let's use a scenario where the kid doesn't match:
    let request_jwt = sign_jws(&request_claims, &daemon_priv, &daemon_kid).unwrap();
    let outer = DaemonAuthClaims {
        request_jwt,
        aud: "https://api.example.com/v1/sign".into(),
        iat: 1_900_000_000 - 30,
        exp: 1_900_000_000,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&outer, &daemon_priv, &daemon_kid).unwrap();

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}
