use axum::response::{IntoResponse, Response};

use crate::error::AppError;

/// Authentication error type used as the rejection for auth extractors.
#[derive(Debug)]
pub enum AuthError {
    /// No `Authorization` header found in the request.
    MissingAuthorizationHeader,
    /// `Authorization` header value is not valid UTF-8.
    InvalidAuthorizationHeader,
    /// `Authorization` header does not use the `Bearer` scheme.
    MissingBearerScheme,
    /// Token could not be decoded, verified, or is expired.
    InvalidToken(String),
    /// Token is valid but the identified entity is not authorized.
    Unauthorized(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthorizationHeader => write!(f, "missing authorization token"),
            Self::InvalidAuthorizationHeader => write!(f, "invalid authorization header"),
            Self::MissingBearerScheme => write!(f, "missing Bearer scheme"),
            Self::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Self::Unauthorized(msg) => write!(f, "{msg}"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        AppError::from(self).into_response()
    }
}

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        AppError::unauthorized(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn missing_authorization_header_returns_401() {
        let response = AuthError::MissingAuthorizationHeader.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn invalid_authorization_header_returns_401() {
        let response = AuthError::InvalidAuthorizationHeader.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn missing_bearer_scheme_returns_401() {
        let response = AuthError::MissingBearerScheme.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn invalid_token_returns_401() {
        let response = AuthError::InvalidToken("bad sig".into()).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unauthorized_returns_401() {
        let response = AuthError::Unauthorized("not allowed".into()).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn display_formatting() {
        assert_eq!(
            AuthError::MissingAuthorizationHeader.to_string(),
            "missing authorization token"
        );
        assert_eq!(
            AuthError::InvalidAuthorizationHeader.to_string(),
            "invalid authorization header"
        );
        assert_eq!(
            AuthError::MissingBearerScheme.to_string(),
            "missing Bearer scheme"
        );
        assert_eq!(
            AuthError::InvalidToken("expired".into()).to_string(),
            "invalid token: expired"
        );
        assert_eq!(
            AuthError::Unauthorized("denied".into()).to_string(),
            "denied"
        );
    }
}
