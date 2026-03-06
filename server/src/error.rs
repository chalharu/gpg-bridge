// ci:max-file-lines 210
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
    Conflict,
    NotFound,
    Gone,
    Database,
    Internal,
    TooManyRequests,
}

/// Optional rate limit metadata attached to 429 responses.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitMeta {
    pub quota: u32,
    pub window_seconds: u64,
    pub remaining: u32,
    pub reset_after_seconds: u64,
}

#[derive(Debug)]
pub struct AppError {
    kind: AppErrorKind,
    detail: String,
    instance: Option<String>,
    rate_limit: Option<RateLimitMeta>,
}

impl AppError {
    fn new(kind: AppErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            instance: None,
            rate_limit: None,
        }
    }

    pub fn not_acceptable(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::NotAcceptable, detail)
    }
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Unauthorized, detail)
    }
    pub fn validation(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Validation, detail)
    }
    pub fn database(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Database, detail)
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Internal, detail)
    }
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Conflict, detail)
    }
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::NotFound, detail)
    }
    pub fn gone(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::Gone, detail)
    }
    pub fn too_many_requests(detail: impl Into<String>) -> Self {
        Self::new(AppErrorKind::TooManyRequests, detail)
    }

    /// Attach rate limit metadata (used for 429 response headers).
    pub fn set_rate_limit_headers(
        &mut self,
        quota: u32,
        window_seconds: u64,
        remaining: u32,
        reset_after_seconds: u64,
    ) {
        self.rate_limit = Some(RateLimitMeta {
            quota,
            window_seconds,
            remaining,
            reset_after_seconds,
        });
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
            AppErrorKind::Conflict => StatusCode::CONFLICT,
            AppErrorKind::NotFound => StatusCode::NOT_FOUND,
            AppErrorKind::Gone => StatusCode::GONE,
            AppErrorKind::Database => StatusCode::SERVICE_UNAVAILABLE,
            AppErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            AppErrorKind::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn title(&self) -> &'static str {
        match self.kind {
            AppErrorKind::NotAcceptable => "Not acceptable",
            AppErrorKind::Unauthorized => "Unauthorized",
            AppErrorKind::Validation => "Validation error",
            AppErrorKind::Conflict => "Conflict",
            AppErrorKind::NotFound => "Not found",
            AppErrorKind::Gone => "Gone",
            AppErrorKind::Database => "Database error",
            AppErrorKind::Internal => "Internal server error",
            AppErrorKind::TooManyRequests => "Too many requests",
        }
    }

    fn problem_type(&self) -> &'static str {
        match self.kind {
            AppErrorKind::NotAcceptable => "https://gpg-bridge.dev/problems/not-acceptable",
            AppErrorKind::Unauthorized => "https://gpg-bridge.dev/problems/unauthorized",
            AppErrorKind::Validation => "https://gpg-bridge.dev/problems/validation",
            AppErrorKind::Conflict => "https://gpg-bridge.dev/problems/conflict",
            AppErrorKind::NotFound => "https://gpg-bridge.dev/problems/not-found",
            AppErrorKind::Gone => "https://gpg-bridge.dev/problems/gone",
            AppErrorKind::Database => "https://gpg-bridge.dev/problems/database",
            AppErrorKind::Internal => "https://gpg-bridge.dev/problems/internal",
            AppErrorKind::TooManyRequests => "https://gpg-bridge.dev/problems/rate-limit",
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
        let rate_limit = self.rate_limit;
        let body = serde_json::to_vec(&self.to_problem_details()).unwrap_or_else(|_| {
            b"{\"type\":\"about:blank\",\"title\":\"Internal server error\",\"status\":500,\"detail\":\"failed to serialize error response\",\"instance\":null}".to_vec()
        });

        let mut response = Response::new(axum::body::Body::from(body));
        *response.status_mut() = status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );

        if let Some(rl) = rate_limit {
            append_rate_limit_response_headers(response.headers_mut(), &rl);
        }

        response
    }
}

/// Append rate limit + Retry-After headers to a 429 error response.
fn append_rate_limit_response_headers(headers: &mut axum::http::HeaderMap, meta: &RateLimitMeta) {
    use crate::http::rate_limit::headers::append_rate_limit_headers;
    use crate::http::rate_limit::sliding_window::RateLimitResult;

    let result = RateLimitResult {
        allowed: false,
        remaining: meta.remaining,
        reset_after_seconds: meta.reset_after_seconds,
        quota: meta.quota,
        window_seconds: meta.window_seconds,
    };
    append_rate_limit_headers(headers, &result);

    if let Ok(v) = HeaderValue::from_str(&meta.reset_after_seconds.to_string()) {
        headers.insert(axum::http::header::RETRY_AFTER, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::rate_limit::headers::{RATE_LIMIT, RATE_LIMIT_POLICY};
    use axum::http::header::RETRY_AFTER;

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

    #[test]
    fn constructors_map_to_expected_problem_details() {
        let cases = [
            (
                AppError::unauthorized("auth failed"),
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "https://gpg-bridge.dev/problems/unauthorized",
            ),
            (
                AppError::conflict("conflict"),
                StatusCode::CONFLICT,
                "Conflict",
                "https://gpg-bridge.dev/problems/conflict",
            ),
            (
                AppError::not_found("missing"),
                StatusCode::NOT_FOUND,
                "Not found",
                "https://gpg-bridge.dev/problems/not-found",
            ),
            (
                AppError::gone("gone"),
                StatusCode::GONE,
                "Gone",
                "https://gpg-bridge.dev/problems/gone",
            ),
            (
                AppError::internal("internal"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "https://gpg-bridge.dev/problems/internal",
            ),
        ];

        for (app_error, expected_status, expected_title, expected_type) in cases {
            let problem = app_error.to_problem_details();
            assert_eq!(problem.status, expected_status.as_u16());
            assert_eq!(problem.title, expected_title);
            assert_eq!(problem.problem_type, expected_type);
        }
    }

    #[test]
    fn too_many_requests_response_includes_rate_limit_headers() {
        let mut error = AppError::too_many_requests("slow down");
        error.set_rate_limit_headers(60, 60, 0, 30);

        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "30");
        assert_eq!(
            response.headers().get(&RATE_LIMIT_POLICY).unwrap(),
            "\"default\";q=60;w=60"
        );
        assert_eq!(
            response.headers().get(&RATE_LIMIT).unwrap(),
            "\"default\";r=0;t=30"
        );
    }

    #[test]
    fn anyhow_error_converts_to_internal_error() {
        let app_error = AppError::from(anyhow::anyhow!("boom"));
        let problem = app_error.to_problem_details();

        assert_eq!(problem.status, 500);
        assert_eq!(problem.title, "Internal server error");
        assert!(problem.detail.contains("internal operation failed: boom"));
    }
}
