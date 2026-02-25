pub mod config;
pub(crate) mod headers;
mod ip_extractor;
pub mod middleware;
pub(crate) mod sliding_window;
mod sse_tracker;
mod tier;

pub use config::RateLimitConfig;
pub use middleware::rate_limit_middleware;
pub use sliding_window::SlidingWindowLimiter;
pub use tier::RateLimitTier;
// TODO: Integrate SseConnectionTracker into SSE route handlers once they are implemented.
pub use sse_tracker::{SseConnectionGuard, SseConnectionTracker};
