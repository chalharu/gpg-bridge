use axum::{
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum AppErrorKind {
    NotAcceptable,
    Unauthorized,
    Validation,
    Database,
    Internal,
}

#[derive(Debug)]
pub struct AppError {
    kind: AppErrorKind,
    detail: String,
    instance: Option<String>,
}

impl AppError {
    pub fn not_acceptable(detail: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::NotAcceptable,
            detail: detail.into(),
            instance: None,
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::Unauthorized,
            detail: detail.into(),
            instance: None,
        }
    }

    pub fn validation(detail: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::Validation,
            detail: detail.into(),
            instance: None,
        }
    }

    pub fn database(detail: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::Database,
            detail: detail.into(),
            instance: None,
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            kind: AppErrorKind::Internal,
            detail: detail.into(),
            instance: None,
        }
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    fn status_code(&self) -> StatusCode {
        match self.kind {
            AppErrorKind::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            AppErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            AppErrorKind::Validation => StatusCode::BAD_REQUEST,
            AppErrorKind::Database => StatusCode::SERVICE_UNAVAILABLE,
            AppErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self.kind {
            AppErrorKind::NotAcceptable => "Not acceptable",
            AppErrorKind::Unauthorized => "Unauthorized",
            AppErrorKind::Validation => "Validation error",
            AppErrorKind::Database => "Database error",
            AppErrorKind::Internal => "Internal server error",
        }
    }

    fn problem_type(&self) -> &'static str {
        match self.kind {
            AppErrorKind::NotAcceptable => "https://gpg-bridge.dev/problems/not-acceptable",
            AppErrorKind::Unauthorized => "https://gpg-bridge.dev/problems/unauthorized",
            AppErrorKind::Validation => "https://gpg-bridge.dev/problems/validation",
            AppErrorKind::Database => "https://gpg-bridge.dev/problems/database",
            AppErrorKind::Internal => "https://gpg-bridge.dev/problems/internal",
        }
    }

    fn to_problem_details(&self) -> ProblemDetails {
        ProblemDetails {
            problem_type: self.problem_type().to_owned(),
            title: self.title().to_owned(),
            status: self.status_code().as_u16(),
            detail: self.detail.clone(),
            instance: self.instance.clone(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self::database(format!("database operation failed: {value}"))
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self::internal(format!("internal operation failed: {value}"))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = serde_json::to_vec(&self.to_problem_details()).unwrap_or_else(|_| {
            b"{\"type\":\"about:blank\",\"title\":\"Internal server error\",\"status\":500,\"detail\":\"failed to serialize error response\",\"instance\":null}".to_vec()
        });

        let mut response = Response::new(axum::body::Body::from(body));
        *response.status_mut() = status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_returns_problem_json() {
        let response = AppError::validation("missing field").into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    #[test]
    fn not_acceptable_error_returns_406_problem_json() {
        let response = AppError::not_acceptable("unsupported media type").into_response();

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    #[test]
    fn sqlx_error_converts_to_database_error() {
        let app_error = AppError::from(sqlx::Error::PoolTimedOut).with_instance("/health");
        let problem = app_error.to_problem_details();

        assert_eq!(problem.title, "Database error");
        assert_eq!(problem.status, 503);
        assert_eq!(problem.instance, Some("/health".to_owned()));
    }
}
