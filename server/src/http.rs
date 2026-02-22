use std::sync::Arc;

use axum::{
    Json, Router,
    extract::Request,
    http::{
        HeaderMap, Method,
        header::{self, HeaderName, HeaderValue},
    },
    middleware::{self, Next},
    response::Response,
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

#[derive(Debug, Clone)]
pub struct AppState {
    pub repository: Arc<dyn SignatureRepository>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
    database_backend: &'static str,
    database_status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiVersion {
    V1,
}

const ACCEPT_VERSION_V1: &str = "application/vnd.gpg-sign.v1+json";

fn parse_accept_version(headers: &HeaderMap) -> Result<ApiVersion, AppError> {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return Ok(ApiVersion::V1);
    };

    let accept = accept
        .to_str()
        .map_err(|_| AppError::not_acceptable("Accept header contains invalid characters"))?;

    for item in accept
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
    {
        let media_type = item.split(';').next().unwrap_or("").trim();

        if media_type == "*/*"
            || media_type == "application/json"
            || media_type == ACCEPT_VERSION_V1
        {
            return Ok(ApiVersion::V1);
        }
    }

    Err(AppError::not_acceptable(format!(
        "unsupported Accept header; use {ACCEPT_VERSION_V1}, application/json, or */*"
    )))
}

async fn accept_version_middleware(req: Request, next: Next) -> Result<Response, AppError> {
    if req.method() != Method::OPTIONS {
        let _ = parse_accept_version(req.headers())?;
    }

    Ok(next.run(req).await)
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;

    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}

pub async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<HealthResponse>, AppError> {
    state
        .repository
        .health_check()
        .await
        .map_err(|error| AppError::from(error).with_instance("/"))?;

    Ok(Json(HealthResponse {
        status: "ok",
        database_backend: state.repository.backend_name(),
        database_status: "ok",
    }))
}

pub fn build_router(state: AppState) -> Router {
    let request_id_header = axum::http::header::HeaderName::from_static("x-request-id");
    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::ACCEPT,
            header::CONTENT_TYPE,
            request_id_header.clone(),
        ]);

    Router::new()
        .route("/", get(health))
        .layer(middleware::from_fn(accept_version_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
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
        http::{Request, StatusCode},
        response::IntoResponse,
    };
    use tower::ServiceExt;

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
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();

        let state = AppState { repository };
        let Json(response) = health(axum::extract::State(state)).await.unwrap();

        assert_eq!(response.status, "ok");
        assert_eq!(response.database_backend, "sqlite");
        assert_eq!(response.database_status, "ok");
    }

    #[tokio::test]
    async fn health_returns_problem_details_when_repository_unavailable() {
        let state = AppState {
            repository: Arc::new(FailingRepository),
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

    #[tokio::test]
    async fn router_rejects_unsupported_accept_with_406() {
        let app = build_router(AppState {
            repository: Arc::new(HealthyRepository),
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .header(header::ACCEPT, "application/vnd.gpg-bridge.v2+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
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
    async fn router_accepts_v1_media_type_and_adds_security_headers() {
        let app = build_router(AppState {
            repository: Arc::new(HealthyRepository),
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .header(header::ACCEPT, ACCEPT_VERSION_V1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
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
    async fn router_handles_cors_preflight_options() {
        let app = build_router(AppState {
            repository: Arc::new(HealthyRepository),
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
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
}
