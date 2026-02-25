use axum::http::HeaderMap;
use axum::http::header::HeaderName;
use axum::http::header::HeaderValue;

use super::sliding_window::RateLimitResult;

/// `RateLimit-Policy` header name.
pub static RATE_LIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");
/// `RateLimit` header name.
pub static RATE_LIMIT: HeaderName = HeaderName::from_static("ratelimit");

/// Attach rate limit informational headers to a response header map.
///
/// Headers follow draft-ietf-httpapi-ratelimit-headers:
/// - `RateLimit-Policy: "default";q=<quota>;w=<window>`
/// - `RateLimit: "default";r=<remaining>;t=<reset>`
pub fn append_rate_limit_headers(headers: &mut HeaderMap, result: &RateLimitResult) {
    let policy = format!("\"default\";q={};w={}", result.quota, result.window_seconds);
    let state = format!(
        "\"default\";r={};t={}",
        result.remaining, result.reset_after_seconds
    );

    if let Ok(v) = HeaderValue::from_str(&policy) {
        headers.insert(RATE_LIMIT_POLICY.clone(), v);
    }
    if let Ok(v) = HeaderValue::from_str(&state) {
        headers.insert(RATE_LIMIT.clone(), v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_result(remaining: u32) -> RateLimitResult {
        RateLimitResult {
            allowed: remaining > 0,
            remaining,
            reset_after_seconds: 30,
            quota: 60,
            window_seconds: 60,
        }
    }

    #[test]
    fn appends_policy_header() {
        let mut headers = HeaderMap::new();
        append_rate_limit_headers(&mut headers, &sample_result(50));

        let policy = headers.get(&RATE_LIMIT_POLICY).unwrap().to_str().unwrap();
        assert_eq!(policy, "\"default\";q=60;w=60");
    }

    #[test]
    fn appends_rate_limit_state_header() {
        let mut headers = HeaderMap::new();
        append_rate_limit_headers(&mut headers, &sample_result(50));

        let state = headers.get(&RATE_LIMIT).unwrap().to_str().unwrap();
        assert_eq!(state, "\"default\";r=50;t=30");
    }

    #[test]
    fn zero_remaining_headers() {
        let mut headers = HeaderMap::new();
        append_rate_limit_headers(&mut headers, &sample_result(0));

        let state = headers.get(&RATE_LIMIT).unwrap().to_str().unwrap();
        assert!(state.contains("r=0"));
    }
}
