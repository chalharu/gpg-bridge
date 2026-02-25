mod accept;
pub mod auth;
mod middleware;

use std::sync::Arc;

use axum::{
    Json, Router,
    http::{
        Method,
        header::{self},
    },
    routing::get,
};
use serde::Serialize;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::Level;

use crate::error::AppError;
use crate::repository::SignatureRepository;

use self::middleware::security_headers_middleware;
use accept::accept_version_middleware;

#[derive(Debug, Clone)]
pub struct AppState {
    pub repository: Arc<dyn SignatureRepository>,
    pub base_url: String,
    pub signing_key_secret: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

pub async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<HealthResponse>, AppError> {
    state
        .repository
        .health_check()
        .await
        .map_err(|error| AppError::from(error).with_instance("/health"))?;

    let _ = state.repository.backend_name();

    Ok(Json(HealthResponse { status: "ok" }))
}

pub fn build_router(state: AppState) -> Router {
    let request_id_header = axum::http::header::HeaderName::from_static("x-request-id");
    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            request_id_header.clone(),
        ]);

    Router::new()
        .route("/health", get(health))
        .layer(axum::middleware::from_fn(accept_version_middleware))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(cors_layer)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{self, Body},
        http::{Request, StatusCode, header::HeaderName},
        response::IntoResponse,
    };
    use tower::ServiceExt;

    use super::accept::ACCEPT_VERSION_V1;
    use crate::{config::AppConfig, repository::build_repository};
    use async_trait::async_trait;

    #[derive(Debug)]
    struct HealthyRepository;

    #[async_trait]
    impl SignatureRepository for HealthyRepository {
        async fn run_migrations(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn backend_name(&self) -> &'static str {
            "sqlite"
        }

        async fn store_signing_key(
            &self,
            _key: &crate::repository::SigningKeyRow,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_active_signing_key(
            &self,
        ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
            unimplemented!()
        }
        async fn get_signing_key_by_kid(
            &self,
            _kid: &str,
        ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
            unimplemented!()
        }
        async fn retire_signing_key(&self, _kid: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_signing_keys(&self, _now: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn get_client_by_id(
            &self,
            _client_id: &str,
        ) -> anyhow::Result<Option<crate::repository::ClientRow>> {
            unimplemented!()
        }
        async fn get_client_pairings(
            &self,
            _client_id: &str,
        ) -> anyhow::Result<Vec<crate::repository::ClientPairingRow>> {
            unimplemented!()
        }
        async fn get_request_by_id(
            &self,
            _request_id: &str,
        ) -> anyhow::Result<Option<crate::repository::RequestRow>> {
            unimplemented!()
        }
        async fn store_jti(&self, _jti: &str, _expired: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_jtis(&self, _now: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
    }

    #[derive(Debug)]
    struct FailingRepository;

    #[async_trait]
    impl SignatureRepository for FailingRepository {
        async fn run_migrations(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn health_check(&self) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("connection refused"))
        }

        fn backend_name(&self) -> &'static str {
            "sqlite"
        }

        async fn store_signing_key(
            &self,
            _key: &crate::repository::SigningKeyRow,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn get_active_signing_key(
            &self,
        ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
            unimplemented!()
        }
        async fn get_signing_key_by_kid(
            &self,
            _kid: &str,
        ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
            unimplemented!()
        }
        async fn retire_signing_key(&self, _kid: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_signing_keys(&self, _now: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
        async fn get_client_by_id(
            &self,
            _client_id: &str,
        ) -> anyhow::Result<Option<crate::repository::ClientRow>> {
            unimplemented!()
        }
        async fn get_client_pairings(
            &self,
            _client_id: &str,
        ) -> anyhow::Result<Vec<crate::repository::ClientPairingRow>> {
            unimplemented!()
        }
        async fn get_request_by_id(
            &self,
            _request_id: &str,
        ) -> anyhow::Result<Option<crate::repository::RequestRow>> {
            unimplemented!()
        }
        async fn store_jti(&self, _jti: &str, _expired: &str) -> anyhow::Result<bool> {
            unimplemented!()
        }
        async fn delete_expired_jtis(&self, _now: &str) -> anyhow::Result<u64> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn health_returns_ok_status() {
        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "sqlite::memory:".to_owned(),
            db_max_connections: 4,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "plain".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
            base_url: "http://localhost:3000".to_owned(),
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();

        let state = AppState {
            repository,
            base_url: "http://localhost:3000".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
        };
        let Json(response) = health(axum::extract::State(state)).await.unwrap();

        assert_eq!(response.status, "ok");
    }

    #[tokio::test]
    async fn health_returns_problem_details_when_repository_unavailable() {
        let state = AppState {
            repository: Arc::new(FailingRepository),
            base_url: "http://localhost:3000".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
        };

        let error = health(axum::extract::State(state)).await.unwrap_err();
        let response = error.into_response();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/problem+json"
        );

        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_text.contains("\"type\""));
        assert!(body_text.contains("\"title\""));
        assert!(body_text.contains("\"status\""));
        assert!(body_text.contains("\"detail\""));
        assert!(body_text.contains("\"instance\""));
    }

    fn test_state(repo: impl SignatureRepository + 'static) -> AppState {
        AppState {
            repository: Arc::new(repo),
            base_url: "http://localhost:3000".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
        }
    }

    #[tokio::test]
    async fn router_rejects_unsupported_accept_with_406() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/vnd.gpg-bridge.v2+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(
            response
                .headers()
                .get(HeaderName::from_static("x-content-type-options"))
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_text.contains("\"type\""));
        assert!(body_text.contains("\"title\""));
        assert!(body_text.contains("\"status\":406"));
        assert!(body_text.contains("\"detail\""));
        assert!(body_text.contains("\"instance\""));
    }

    #[tokio::test]
    async fn router_accepts_v1_media_type_and_adds_security_headers() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, ACCEPT_VERSION_V1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_VERSION_V1
        );
        assert!(
            response
                .headers()
                .get(header::VARY)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Accept")
        );
        assert_eq!(
            response
                .headers()
                .get(HeaderName::from_static("x-content-type-options"))
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn router_accepts_application_json_and_returns_versioned_content_type() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_VERSION_V1
        );
    }

    #[tokio::test]
    async fn router_accepts_mixed_case_media_type() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "Application/Vnd.Gpg-Sign.V1+Json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_VERSION_V1
        );
    }

    #[tokio::test]
    async fn router_rejects_accept_media_type_with_zero_quality() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/json;q=0, text/plain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn router_accepts_application_wildcard() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_VERSION_V1
        );
    }

    #[tokio::test]
    async fn router_handles_cors_preflight_options() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/health")
                    .header(header::ORIGIN, "https://example.com")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("GET")
        );
    }

    #[tokio::test]
    async fn router_cors_preflight_allows_authorization_header() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/health")
                    .header(header::ORIGIN, "https://example.com")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "authorization,content-type",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT);

        let allow_headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(allow_headers.contains("authorization"));
        assert!(allow_headers.contains("content-type"));
    }

    #[tokio::test]
    async fn router_cors_preflight_allows_patch_and_delete_methods() {
        let app = build_router(test_state(HealthyRepository));

        for request_method in [Method::PATCH, Method::DELETE] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri("/health")
                        .header(header::ORIGIN, "https://example.com")
                        .header(
                            header::ACCESS_CONTROL_REQUEST_METHOD,
                            request_method.as_str(),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert!(
                response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT
            );

            let allow_methods = response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(allow_methods.contains("PATCH"));
            assert!(allow_methods.contains("DELETE"));
        }
    }

    #[tokio::test]
    async fn router_accepts_uppercase_q_parameter_name() {
        let app = build_router(test_state(HealthyRepository));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/json;Q=0.8")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
