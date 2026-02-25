use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::AppError;

use super::config::RateLimitConfig;
use super::headers::append_rate_limit_headers;
use super::ip_extractor::extract_client_ip;
use super::sliding_window::SlidingWindowLimiter;
use super::tier::classify_tier;

/// Shared rate limiter state injected into routers.
#[derive(Clone)]
pub struct RateLimiterState {
    pub limiter: Arc<SlidingWindowLimiter>,
    pub config: RateLimitConfig,
}

/// Axum middleware that enforces per-IP sliding window rate limits.
///
/// On 429, returns ProblemDetails JSON with `Retry-After`,
/// `RateLimit-Policy`, and `RateLimit` headers.
pub async fn rate_limit_middleware(
    State(rl): State<RateLimiterState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract ConnectInfo from request extensions (set by into_make_service_with_connect_info).
    let connect_info = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .cloned();
    let ip = extract_client_ip(req.headers(), connect_info.as_ref())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let tier = classify_tier(req.method(), req.uri().path());
    let tier_config = select_tier_config(&rl.config, tier);

    let result = rl.limiter.check_and_record(ip, tier, tier_config);

    if !result.allowed {
        return Err(build_rejection(result));
    }

    let mut response = next.run(req).await;
    append_rate_limit_headers(response.headers_mut(), &result);
    Ok(response)
}

/// Select the tier configuration matching the classified tier.
fn select_tier_config(
    config: &RateLimitConfig,
    tier: super::tier::RateLimitTier,
) -> &super::config::TierConfig {
    match tier {
        super::tier::RateLimitTier::Strict => &config.strict,
        super::tier::RateLimitTier::Standard => &config.standard,
    }
}

/// Build a 429 AppError with rate limit headers.
fn build_rejection(result: super::sliding_window::RateLimitResult) -> AppError {
    let mut err = AppError::too_many_requests("rate limit exceeded");
    err.set_rate_limit_headers(
        result.quota,
        result.window_seconds,
        result.remaining,
        result.reset_after_seconds,
    );
    err
}

#[cfg(test)]
mod tests {
    use super::super::config::{SseConnectionConfig, TierConfig};
    use super::*;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            strict: TierConfig {
                quota: 2,
                window_seconds: 60,
            },
            standard: TierConfig {
                quota: 5,
                window_seconds: 60,
            },
            sse: SseConnectionConfig {
                max_per_ip: 20,
                max_per_key: 1,
            },
        }
    }

    #[test]
    fn selects_strict_tier_config() {
        let cfg = test_config();
        let tier_cfg = select_tier_config(&cfg, super::super::tier::RateLimitTier::Strict);
        assert_eq!(tier_cfg.quota, 2);
    }

    #[test]
    fn selects_standard_tier_config() {
        let cfg = test_config();
        let tier_cfg = select_tier_config(&cfg, super::super::tier::RateLimitTier::Standard);
        assert_eq!(tier_cfg.quota, 5);
    }

    #[test]
    fn rate_limiter_state_is_cloneable() {
        let state = RateLimiterState {
            limiter: Arc::new(SlidingWindowLimiter::new()),
            config: test_config(),
        };
        let _cloned = state.clone();
    }
}
