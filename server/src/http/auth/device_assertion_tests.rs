use super::*;
use crate::http::auth::test_support::{
    DeviceAssertionFixture, TEST_AUD, TEST_CLIENT_ID, TEST_EXP_FUTURE, TEST_EXP_PAST,
    TEST_IAT_OFFSET, TEST_WIDE_WINDOW, TEST_WRONG_AUD, build_device_assertion_app,
    device_assertion_repo, get_sign_status, make_auth_state,
};

// ---- Helpers ----

// ---- Tests ----

#[tokio::test]
async fn valid_device_assertion_succeeds() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(true);
    let token = fixture.token(TEST_AUD);
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
    let fixture = DeviceAssertionFixture::new();
    let other_fixture = DeviceAssertionFixture::new();
    // Client has a different key than the one used to sign
    let client = other_fixture.client_row();
    let app =
        build_device_assertion_app(make_auth_state(device_assertion_repo(Some(client), true)));

    // Token signed with `priv_jwk` but client has `other_pub`
    // The kid won't match, so we'll get "no public key found"
    let token = fixture.token(TEST_AUD);
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn client_not_found_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = build_device_assertion_app(make_auth_state(device_assertion_repo(None, true)));

    let token = fixture.token(TEST_AUD);
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_aud_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(true);

    // Token has wrong audience
    let token = fixture.token(TEST_WRONG_AUD);
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_token_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(true);
    let token = fixture.token_for_claims(&DeviceAssertionClaims {
        iss: TEST_CLIENT_ID.into(),
        sub: TEST_CLIENT_ID.into(),
        aud: TEST_AUD.into(),
        exp: TEST_EXP_PAST,
        iat: TEST_EXP_PAST - TEST_IAT_OFFSET,
        jti: uuid::Uuid::new_v4().to_string(),
    });

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn iss_ne_sub_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(true);
    let token = fixture.token_for_claims(&DeviceAssertionClaims {
        iss: "different-fid".into(),
        sub: TEST_CLIENT_ID.into(),
        aud: TEST_AUD.into(),
        exp: TEST_EXP_FUTURE,
        iat: TEST_EXP_FUTURE - TEST_IAT_OFFSET,
        jti: uuid::Uuid::new_v4().to_string(),
    });

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jti_replay_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(false);
    let token = fixture.token(TEST_AUD);
    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn exp_window_too_large_returns_401() {
    let fixture = DeviceAssertionFixture::new();
    let app = fixture.app(true);

    // exp - iat = 120 > 60 → rejected
    let token = fixture.token_for_claims(&DeviceAssertionClaims {
        iss: TEST_CLIENT_ID.into(),
        sub: TEST_CLIENT_ID.into(),
        aud: TEST_AUD.into(),
        exp: TEST_EXP_FUTURE,
        iat: TEST_EXP_FUTURE - TEST_WIDE_WINDOW,
        jti: uuid::Uuid::new_v4().to_string(),
    });

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}
