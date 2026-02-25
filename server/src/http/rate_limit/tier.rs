use axum::http::Method;

/// Rate limit tier applied to an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitTier {
    /// Strict tier: unauthenticated resource-creation endpoints.
    Strict,
    /// Standard tier: all other endpoints.
    Standard,
}

/// Classify a request into a rate limit tier based on method and path.
///
/// Strict tier applies to:
/// - `POST /device`
/// - `GET /pairing-token`
///
/// Everything else falls into the Standard tier.
pub fn classify_tier(method: &Method, path: &str) -> RateLimitTier {
    let normalized = path.trim_end_matches('/');

    match (method, normalized) {
        (&Method::POST, "/device") => RateLimitTier::Strict,
        (&Method::GET, "/pairing-token") => RateLimitTier::Strict,
        _ => RateLimitTier::Standard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_device_is_strict() {
        assert_eq!(
            classify_tier(&Method::POST, "/device"),
            RateLimitTier::Strict
        );
    }

    #[test]
    fn get_pairing_token_is_strict() {
        assert_eq!(
            classify_tier(&Method::GET, "/pairing-token"),
            RateLimitTier::Strict
        );
    }

    #[test]
    fn get_device_is_standard() {
        assert_eq!(
            classify_tier(&Method::GET, "/device"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn post_pairing_token_is_standard() {
        assert_eq!(
            classify_tier(&Method::POST, "/pairing-token"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn get_health_is_standard() {
        assert_eq!(
            classify_tier(&Method::GET, "/health"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn post_sign_request_is_standard() {
        assert_eq!(
            classify_tier(&Method::POST, "/sign-request"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn trailing_slash_is_normalized() {
        assert_eq!(
            classify_tier(&Method::POST, "/device/"),
            RateLimitTier::Strict
        );
    }

    #[test]
    fn unknown_path_is_standard() {
        assert_eq!(
            classify_tier(&Method::GET, "/unknown"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn delete_pairing_is_standard() {
        assert_eq!(
            classify_tier(&Method::DELETE, "/pairing/some-id"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn get_sign_events_is_standard() {
        assert_eq!(
            classify_tier(&Method::GET, "/sign-events"),
            RateLimitTier::Standard
        );
    }

    #[test]
    fn get_pairing_session_is_standard() {
        assert_eq!(
            classify_tier(&Method::GET, "/pairing-session"),
            RateLimitTier::Standard
        );
    }
}
