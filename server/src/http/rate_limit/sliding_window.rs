use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::config::TierConfig;
use super::tier::RateLimitTier;

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining quota in the current window.
    pub remaining: u32,
    /// Seconds until the earliest entry in the window expires.
    pub reset_after_seconds: u64,
    /// Configured quota for this tier.
    pub quota: u32,
    /// Window duration in seconds.
    pub window_seconds: u64,
}

/// Per-tier sliding window state for one (IP, tier) pair.
struct IpWindow {
    timestamps: VecDeque<Instant>,
}

/// Thread-safe in-memory sliding window rate limiter.
///
/// Each (IP, tier) pair maintains an independent sliding window,
/// so Strict and Standard quotas are fully isolated.
pub struct SlidingWindowLimiter {
    state: Mutex<HashMap<(IpAddr, RateLimitTier), IpWindow>>,
}

impl Default for SlidingWindowLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindowLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check and record a request. Returns the rate limit result.
    ///
    /// Each (IP, tier) pair has its own independent sliding window.
    pub fn check_and_record(
        &self,
        ip: IpAddr,
        tier: RateLimitTier,
        tier_config: &TierConfig,
    ) -> RateLimitResult {
        let now = Instant::now();
        let window = Duration::from_secs(tier_config.window_seconds);
        let mut state = self.state.lock().expect("rate limiter lock poisoned");

        let entry = state.entry((ip, tier)).or_insert_with(|| IpWindow {
            timestamps: VecDeque::new(),
        });

        evict_expired(&mut entry.timestamps, now, window);

        let count = entry.timestamps.len() as u32;
        let reset_after = compute_reset_after(entry.timestamps.front(), now, window);

        if count >= tier_config.quota {
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after_seconds: reset_after,
                quota: tier_config.quota,
                window_seconds: tier_config.window_seconds,
            };
        }

        entry.timestamps.push_back(now);
        let remaining = tier_config.quota - count - 1;

        RateLimitResult {
            allowed: true,
            remaining,
            reset_after_seconds: reset_after,
            quota: tier_config.quota,
            window_seconds: tier_config.window_seconds,
        }
    }

    /// Remove entries for IPs that have no timestamps within
    /// any active window. Call periodically to prevent memory leaks.
    pub fn cleanup(&self, max_window: Duration) {
        let now = Instant::now();
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        state.retain(|_key, entry| {
            evict_expired(&mut entry.timestamps, now, max_window);
            !entry.timestamps.is_empty()
        });
    }

    /// Spawn a background task that runs [`cleanup`](Self::cleanup)
    /// at a fixed interval. The task runs until the Tokio runtime shuts down.
    pub fn spawn_cleanup_task(self: &Arc<Self>, interval: Duration, max_window: Duration) {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                limiter.cleanup(max_window);
            }
        });
    }
}

/// Remove timestamps older than the window from the front of the deque.
fn evict_expired(timestamps: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    while timestamps.front().is_some_and(|&ts| ts <= cutoff) {
        timestamps.pop_front();
    }
}

/// Compute seconds until the oldest entry in the window expires.
fn compute_reset_after(oldest: Option<&Instant>, now: Instant, window: Duration) -> u64 {
    oldest
        .map(|ts| {
            let expires_at = *ts + window;
            if expires_at > now {
                (expires_at - now).as_secs() + 1
            } else {
                1
            }
        })
        .unwrap_or(window.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_tier() -> TierConfig {
        TierConfig {
            quota: 3,
            window_seconds: 60,
        }
    }

    fn standard_tier() -> TierConfig {
        TierConfig {
            quota: 10,
            window_seconds: 60,
        }
    }

    #[test]
    fn allows_requests_within_quota() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tier = strict_tier();

        let r1 = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert!(r1.allowed);
        assert_eq!(r1.remaining, 2);

        let r2 = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert!(r2.allowed);
        assert_eq!(r2.remaining, 1);

        let r3 = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert!(r3.allowed);
        assert_eq!(r3.remaining, 0);
    }

    #[test]
    fn rejects_requests_over_quota() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tier = strict_tier();

        for _ in 0..3 {
            limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        }

        let result = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[test]
    fn different_ips_have_separate_windows() {
        let limiter = SlidingWindowLimiter::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let tier = strict_tier();

        for _ in 0..3 {
            limiter.check_and_record(ip1, RateLimitTier::Strict, &tier);
        }

        let result = limiter.check_and_record(ip2, RateLimitTier::Strict, &tier);
        assert!(result.allowed);
        assert_eq!(result.remaining, 2);
    }

    #[test]
    fn strict_and_standard_tiers_are_isolated() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let strict = strict_tier();
        let standard = standard_tier();

        // Exhaust the strict tier quota.
        for _ in 0..3 {
            limiter.check_and_record(ip, RateLimitTier::Strict, &strict);
        }
        let strict_result = limiter.check_and_record(ip, RateLimitTier::Strict, &strict);
        assert!(!strict_result.allowed, "strict should be exhausted");

        // Standard tier must still be fully available.
        let standard_result = limiter.check_and_record(ip, RateLimitTier::Standard, &standard);
        assert!(
            standard_result.allowed,
            "standard should still be available"
        );
        assert_eq!(standard_result.remaining, 9);
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tier = TierConfig {
            quota: 3,
            window_seconds: 0, // immediate expiry
        };

        limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        limiter.cleanup(Duration::from_secs(0));

        let state = limiter.state.lock().unwrap();
        assert!(
            !state.contains_key(&(ip, RateLimitTier::Strict)),
            "expired entry should be cleaned up"
        );
    }

    #[test]
    fn reset_after_is_positive() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tier = strict_tier();

        let result = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert!(result.reset_after_seconds > 0);
    }

    #[test]
    fn result_contains_tier_info() {
        let limiter = SlidingWindowLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tier = strict_tier();

        let result = limiter.check_and_record(ip, RateLimitTier::Strict, &tier);
        assert_eq!(result.quota, 3);
        assert_eq!(result.window_seconds, 60);
    }
}
