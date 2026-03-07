use crate::http::auth::test_support::{
    DaemonAuthFixture, TEST_AUD, TEST_REQUEST_ID, TEST_WRONG_AUD, build_daemon_auth_app,
    daemon_auth_repo, get_sign_status, make_auth_state,
};
use crate::jwt::{generate_signing_key_pair, jwk_to_json};
use crate::repository::RequestRow;
use crate::test_support::make_signing_key_row;

// ---- Tests ----

#[tokio::test]
async fn valid_daemon_auth_succeeds() {
    let fixture = DaemonAuthFixture::new();
    let app = fixture.app(Some(fixture.request_row()), true);
    let token = fixture.token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let app = build_daemon_auth_app(make_auth_state(daemon_auth_repo(None, None, true)));

    assert_eq!(
        get_sign_status(app, None).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_daemon_key_returns_401() {
    let fixture = DaemonAuthFixture::new();
    let (_wrong_priv, wrong_pub, _wrong_kid) = generate_signing_key_pair().unwrap();

    // DB has wrong_pub as daemon key, but token is signed with daemon_priv
    let request = RequestRow {
        request_id: TEST_REQUEST_ID.into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&wrong_pub).unwrap(),
    };
    let app = fixture.app(Some(request), true);
    let token = fixture.token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn request_not_found_returns_401() {
    let fixture = DaemonAuthFixture::new();
    let app = fixture.app(None, true);
    let token = fixture.token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_aud_returns_401() {
    let fixture = DaemonAuthFixture::new();
    let app = fixture.app(Some(fixture.request_row()), true);
    let token = fixture.token(TEST_REQUEST_ID, TEST_WRONG_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jti_replay_returns_401() {
    let fixture = DaemonAuthFixture::new();
    let app = fixture.app(Some(fixture.request_row()), false);
    let token = fixture.token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_outer_jws_returns_401() {
    let fixture = DaemonAuthFixture::new();
    let app = fixture.app(Some(fixture.request_row()), true);
    let token = fixture.expired_outer_token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn invalid_request_jwt_returns_401() {
    let fixture = DaemonAuthFixture::new();

    // Use a different server key for signing the request_jwt (wrong key)
    let (other_priv, other_pub, other_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&other_priv, &other_pub, &other_kid);

    let request = RequestRow {
        request_id: TEST_REQUEST_ID.into(),
        status: "created".into(),
        daemon_public_key: jwk_to_json(&fixture.daemon_pub).unwrap(),
    };
    let repo = daemon_auth_repo(Some(sk), Some(request), true);
    let app = build_daemon_auth_app(make_auth_state(repo));
    let token = fixture.invalid_request_token(TEST_REQUEST_ID, TEST_AUD);

    assert_eq!(
        get_sign_status(app, Some(&token)).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}
