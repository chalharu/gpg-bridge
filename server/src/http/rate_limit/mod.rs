pub mod config;
pub(crate) mod headers;
pub(crate) mod ip_extractor;
pub mod middleware;
pub(crate) mod sliding_window;
pub(crate) mod sse_request;
pub(crate) mod sse_tracker;
mod tier;

pub use config::RateLimitConfig;
pub use middleware::rate_limit_middleware;
pub use sliding_window::SlidingWindowLimiter;
pub(crate) use sse_request::{acquire_sse_slot, resolve_client_ip};
pub use sse_tracker::{SseConnectionGuard, SseConnectionTracker};
pub use tier::RateLimitTier;
