use std::sync::Arc;

use axum::{Json, Router, routing::get};
use serde::Serialize;
use tower_http::{
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

    Router::new()
        .route("/", get(health))
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
    use crate::{config::AppConfig, repository::build_repository};
    use async_trait::async_trait;
    use axum::{body, response::IntoResponse};

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
}
