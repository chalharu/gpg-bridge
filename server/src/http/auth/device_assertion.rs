use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::jwt::{DeviceAssertionClaims, decode_jws_unverified, extract_kid, verify_jws_with_key};

use super::error::AuthError;
use super::{
    build_expected_aud, extract_bearer_token, find_public_key_by_kid, timestamp_to_rfc3339,
};
use crate::http::AppState;

/// Authenticated device identity extracted from `Authorization: Bearer`.
#[derive(Debug, Clone)]
pub struct DeviceAssertionAuth {
    pub client_id: String,
}

impl FromRequestParts<AppState> for DeviceAssertionAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let unverified: DeviceAssertionClaims =
            decode_jws_unverified(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let kid = extract_kid(&token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let client = state
            .repository
            .get_client_by_id(&unverified.sub)
            .await
            .map_err(AppError::from)?
            .ok_or(AuthError::Unauthorized("client not found".into()))?;

        let public_jwk = find_public_key_by_kid(&client.public_keys, &kid)?;
        let claims: DeviceAssertionClaims = verify_jws_with_key(&token, &public_jwk)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // Validate iss==sub on verified claims (defense-in-depth)
        validate_iss_eq_sub(&claims)?;
        validate_aud(&claims, &build_expected_aud(&state.base_url, parts))?;
        validate_exp_window(&claims)?;
        store_jti(state, &claims.jti, claims.exp).await?;

        Ok(Self {
            client_id: claims.sub,
        })
    }
}

fn validate_iss_eq_sub(claims: &DeviceAssertionClaims) -> Result<(), AuthError> {
    if claims.iss != claims.sub {
        return Err(AuthError::InvalidToken("iss must equal sub".into()));
    }
    Ok(())
}

fn validate_aud(claims: &DeviceAssertionClaims, expected: &str) -> Result<(), AuthError> {
    if claims.aud != expected {
        return Err(AuthError::InvalidToken("aud mismatch".into()));
    }
    Ok(())
}

/// Enforce a maximum token lifetime of 60 seconds (`exp - iat <= 60`).
fn validate_exp_window(claims: &DeviceAssertionClaims) -> Result<(), AuthError> {
    const MAX_WINDOW_SECS: i64 = 60;
    let window = claims.exp.saturating_sub(claims.iat);
    if window > MAX_WINDOW_SECS || window <= 0 {
        return Err(AuthError::InvalidToken(
            "token lifetime out of range".into(),
        ));
    }
    Ok(())
}

async fn store_jti(state: &AppState, jti: &str, exp: i64) -> Result<(), AppError> {
    let expired = timestamp_to_rfc3339(exp)?;
    let stored = state
        .repository
        .store_jti(jti, &expired)
        .await
        .map_err(AppError::from)?;
    if !stored {
        return Err(AuthError::InvalidToken("jti replay detected".into()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{generate_signing_key_pair, jwk_to_json, sign_jws};
    use crate::repository::{
        ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use axum::{Json, Router};
    use std::sync::Arc;
    use tower::ServiceExt;

    // ---- Mock repository ----

    #[derive(Debug)]
    struct MockRepo {
        client: Option<ClientRow>,
        jti_accepted: bool,
    }

    impl MockRepo {
        fn with_client(client: ClientRow) -> Self {
            Self {
                client: Some(client),
                jti_accepted: true,
            }
        }

        fn with_replay() -> Self {
            Self {
                client: None,
                jti_accepted: false,
            }
        }
    }

    #[async_trait]
    impl SignatureRepository for MockRepo {
        async fn run_migrations(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn backend_name(&self) -> &'static str {
            "mock"
        }
        async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
            unimplemented!()
        }
        async fn get_signing_key_by_kid(&self, _: &str) -> anyhow::Result<Option<SigningKeyRow>> {
            unimplemented!()
        }
        async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn get_client_by_id(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
            Ok(self.client.clone())
        }
        async fn get_client_pairings(&self, _: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
            Ok(vec![])
        }
        async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
            Ok(None)
        }
        async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
            Ok(self.jti_accepted)
        }
        async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
            Ok(0)
        }
    }

    // ---- Helpers ----

    fn make_state(repo: impl SignatureRepository + 'static) -> AppState {
        AppState {
            repository: Arc::new(repo),
            base_url: "https://api.example.com".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
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
            public_keys: format!("[{pub_json}]"),
            default_kid: kid.into(),
        }
    }

    // ---- Tests ----

    #[tokio::test]
    async fn valid_device_assertion_succeeds() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let client = make_client_row(&pub_jwk, &kid);
        let state = make_state(MockRepo::with_client(client));
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
        let state = make_state(MockRepo::with_replay());
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
        let state = make_state(MockRepo::with_client(client));
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
        let repo = MockRepo {
            client: None,
            jti_accepted: true,
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
    async fn wrong_aud_returns_401() {
        let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
        let client = make_client_row(&pub_jwk, &kid);
        let state = make_state(MockRepo::with_client(client));
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
        let state = make_state(MockRepo::with_client(client));
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
        let state = make_state(MockRepo::with_client(client));
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
            public_keys: format!("[{pub_json}]"),
            default_kid: kid.clone(),
        };
        let repo = MockRepo {
            client: Some(client),
            jti_accepted: false, // simulate replay
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
        let state = make_state(MockRepo::with_client(client));
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
}
