use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use josekit::jwk::Jwk;
use tower::ServiceExt;

use crate::http::AppState;
use crate::repository::{ClientRow, RequestRow, SigningKeyRow};
use crate::test_support::{MockRepository, make_test_app_state};

pub(crate) fn make_auth_state(repo: MockRepository) -> AppState {
    make_test_app_state(repo)
}

pub(crate) fn daemon_auth_repo(
    signing_key: Option<SigningKeyRow>,
    request: Option<RequestRow>,
    jti_accepted: bool,
) -> MockRepository {
    MockRepository {
        signing_key,
        request: std::sync::Mutex::new(request),
        jti_accepted,
        ..Default::default()
    }
}

pub(crate) fn device_assertion_repo(
    client: Option<ClientRow>,
    jti_accepted: bool,
) -> MockRepository {
    MockRepository {
        clients: std::sync::Mutex::new(client.into_iter().collect()),
        jti_accepted,
        ..Default::default()
    }
}

pub(crate) fn make_device_client_row(pub_jwk: &Jwk, kid: &str) -> ClientRow {
    let pub_json = crate::jwt::jwk_to_json(pub_jwk).unwrap();
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

pub(crate) fn build_daemon_auth_app(state: AppState) -> Router {
    async fn handler(_auth: crate::http::auth::DaemonAuthJws) -> Json<String> {
        Json("ok".into())
    }

    Router::new()
        .route("/v1/sign", get(handler))
        .with_state(state)
}

pub(crate) fn build_device_assertion_app(state: AppState) -> Router {
    async fn handler(_auth: crate::http::auth::DeviceAssertionAuth) -> Json<String> {
        Json("ok".into())
    }

    Router::new()
        .route("/v1/sign", get(handler))
        .with_state(state)
}

pub(crate) async fn get_sign_status(app: Router, token: Option<&str>) -> StatusCode {
    let mut request = Request::get("/v1/sign");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}
