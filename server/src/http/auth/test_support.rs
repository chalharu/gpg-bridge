use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use josekit::jwk::Jwk;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DaemonAuthClaims, DeviceAssertionClaims, PayloadType, RequestClaims, generate_signing_key_pair,
    jwk_to_json, sign_jws,
};
use crate::repository::{ClientRow, RequestRow, SigningKeyRow};
use crate::test_support::{MockRepository, make_signing_key_row, make_test_app_state};

pub(crate) const TEST_REQUEST_ID: &str = "req-1";
pub(crate) const TEST_CLIENT_ID: &str = "fid-1";
pub(crate) const TEST_AUD: &str = "https://api.example.com/v1/sign";
pub(crate) const TEST_WRONG_AUD: &str = "https://wrong.example.com/v1/sign";
pub(crate) const TEST_EXP_FUTURE: i64 = 1_900_000_000;
pub(crate) const TEST_EXP_PAST: i64 = 1_000_000_000;
pub(crate) const TEST_IAT_OFFSET: i64 = 30;
pub(crate) const TEST_WIDE_WINDOW: i64 = 120;

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
    let pub_json = jwk_to_json(pub_jwk).unwrap();
    ClientRow {
        client_id: TEST_CLIENT_ID.into(),
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

pub(crate) struct DaemonAuthFixture {
    pub(crate) server_priv: Jwk,
    pub(crate) server_pub: Jwk,
    pub(crate) server_kid: String,
    pub(crate) daemon_priv: Jwk,
    pub(crate) daemon_pub: Jwk,
    pub(crate) daemon_kid: String,
}

impl DaemonAuthFixture {
    pub(crate) fn new() -> Self {
        let (server_priv, server_pub, server_kid) = generate_signing_key_pair().unwrap();
        let (daemon_priv, daemon_pub, daemon_kid) = generate_signing_key_pair().unwrap();
        Self {
            server_priv,
            server_pub,
            server_kid,
            daemon_priv,
            daemon_pub,
            daemon_kid,
        }
    }

    pub(crate) fn signing_key_row(&self) -> SigningKeyRow {
        make_signing_key_row(&self.server_priv, &self.server_pub, &self.server_kid)
    }

    pub(crate) fn request_row(&self) -> RequestRow {
        RequestRow {
            request_id: TEST_REQUEST_ID.into(),
            status: "created".into(),
            daemon_public_key: jwk_to_json(&self.daemon_pub).unwrap(),
        }
    }

    pub(crate) fn app(&self, request: Option<RequestRow>, jti_accepted: bool) -> Router {
        build_daemon_auth_app(make_auth_state(daemon_auth_repo(
            Some(self.signing_key_row()),
            request,
            jti_accepted,
        )))
    }

    pub(crate) fn token(&self, request_id: &str, aud: &str) -> String {
        let request_claims = RequestClaims {
            sub: request_id.into(),
            payload_type: PayloadType::Request,
            exp: TEST_EXP_FUTURE,
        };
        let request_jwt = sign_jws(&request_claims, &self.server_priv, &self.server_kid).unwrap();

        let outer_claims = DaemonAuthClaims {
            request_jwt,
            aud: aud.into(),
            iat: TEST_EXP_FUTURE - TEST_IAT_OFFSET,
            exp: TEST_EXP_FUTURE,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        sign_jws(&outer_claims, &self.daemon_priv, &self.daemon_kid).unwrap()
    }

    pub(crate) fn expired_outer_token(&self, request_id: &str, aud: &str) -> String {
        let request_claims = RequestClaims {
            sub: request_id.into(),
            payload_type: PayloadType::Request,
            exp: TEST_EXP_FUTURE,
        };
        let request_jwt = sign_jws(&request_claims, &self.server_priv, &self.server_kid).unwrap();
        let outer_claims = DaemonAuthClaims {
            request_jwt,
            aud: aud.into(),
            iat: TEST_EXP_PAST - TEST_IAT_OFFSET,
            exp: TEST_EXP_PAST,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        sign_jws(&outer_claims, &self.daemon_priv, &self.daemon_kid).unwrap()
    }

    pub(crate) fn invalid_request_token(&self, request_id: &str, aud: &str) -> String {
        let request_claims = RequestClaims {
            sub: request_id.into(),
            payload_type: PayloadType::Request,
            exp: TEST_EXP_FUTURE,
        };
        let request_jwt = sign_jws(&request_claims, &self.daemon_priv, &self.daemon_kid).unwrap();
        let outer_claims = DaemonAuthClaims {
            request_jwt,
            aud: aud.into(),
            iat: TEST_EXP_FUTURE - TEST_IAT_OFFSET,
            exp: TEST_EXP_FUTURE,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        sign_jws(&outer_claims, &self.daemon_priv, &self.daemon_kid).unwrap()
    }
}

pub(crate) struct DeviceAssertionFixture {
    pub(crate) priv_jwk: Jwk,
    pub(crate) pub_jwk: Jwk,
    pub(crate) kid: String,
}

impl DeviceAssertionFixture {
    pub(crate) fn new() -> Self {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        Self {
            priv_jwk,
            pub_jwk,
            kid,
        }
    }

    pub(crate) fn client_row(&self) -> ClientRow {
        make_device_client_row(&self.pub_jwk, &self.kid)
    }

    pub(crate) fn app(&self, jti_accepted: bool) -> Router {
        build_device_assertion_app(make_auth_state(device_assertion_repo(
            Some(self.client_row()),
            jti_accepted,
        )))
    }

    pub(crate) fn valid_claims(&self, aud: &str) -> DeviceAssertionClaims {
        DeviceAssertionClaims {
            iss: TEST_CLIENT_ID.into(),
            sub: TEST_CLIENT_ID.into(),
            aud: aud.into(),
            exp: TEST_EXP_FUTURE,
            iat: TEST_EXP_FUTURE - TEST_IAT_OFFSET,
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub(crate) fn token_for_claims(&self, claims: &DeviceAssertionClaims) -> String {
        sign_jws(claims, &self.priv_jwk, &self.kid).unwrap()
    }

    pub(crate) fn token(&self, aud: &str) -> String {
        self.token_for_claims(&self.valid_claims(aud))
    }
}
