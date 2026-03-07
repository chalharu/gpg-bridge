use super::*;
use crate::http::auth::test_support::{
    build_device_assertion_app, device_assertion_repo, get_sign_status, make_auth_state,
    make_device_client_row,
};
use crate::jwt::{generate_signing_key_pair, sign_jws};

// ---- Helpers ----

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

// ---- Tests ----

#[tokio::test]
async fn valid_device_assertion_succeeds() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let app = build_device_assertion_app(make_auth_state(device_assertion_repo(None, false)));

    assert_eq!(
        get_sign_status(app, None).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_key_returns_401() {
    let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let (_other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
    // Client has a different key than the one used to sign
    let client = make_device_client_row(&other_pub, &other_kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    // Token signed with `priv_jwk` but client has `other_pub`
    // The kid won't match, so we'll get "no public key found"
    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn client_not_found_returns_401() {
    let (priv_jwk, _pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let app = build_device_assertion_app(make_auth_state(device_assertion_repo(None, true)));

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_aud_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    // Token has wrong audience
    let token = make_valid_token(&priv_jwk, &kid, "https://wrong.example.com/v1/sign");
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_token_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    let claims = DeviceAssertionClaims {
        iss: "fid-1".into(),
        sub: "fid-1".into(),
        aud: "https://api.example.com/v1/sign".into(),
        exp: 1_000_000_000, // past
        iat: 1_000_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn iss_ne_sub_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    let claims = DeviceAssertionClaims {
        iss: "different-fid".into(),
        sub: "fid-1".into(),
        aud: "https://api.example.com/v1/sign".into(),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let token = sign_jws(&claims, &priv_jwk, &kid).unwrap();

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jti_replay_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), false)));

    let token = make_valid_token(&priv_jwk, &kid, "https://api.example.com/v1/sign");
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn exp_window_too_large_returns_401() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let client = make_device_client_row(&pub_jwk, &kid);
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

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

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}
