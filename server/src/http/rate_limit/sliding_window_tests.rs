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

// -----------------------------------------------------------------------
// compute_reset_after unit tests (kills +/- and >/</== mutations)
// -----------------------------------------------------------------------

#[test]
fn compute_reset_after_with_none_returns_window() {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    assert_eq!(compute_reset_after(None, now, window), 60);
}

#[test]
fn compute_reset_after_oldest_still_in_window() {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // oldest is 10s ago → expires_at = oldest + 60 = now + 50
    // reset = (now + 50 - now).as_secs() + 1 = 51
    let oldest = now - Duration::from_secs(10);
    let result = compute_reset_after(Some(&oldest), now, window);
    assert_eq!(result, 51);
}

#[test]
fn compute_reset_after_oldest_just_now() {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // oldest == now → expires_at = now + 60
    // reset = 60.as_secs() + 1 = 61
    let result = compute_reset_after(Some(&now), now, window);
    assert_eq!(result, 61);
}

#[test]
fn compute_reset_after_expired_returns_one() {
    let now = Instant::now();
    let window = Duration::from_secs(10);
    // oldest is 20s ago → expires_at = oldest + 10 = now - 10
    // expires_at <= now → returns 1
    let oldest = now - Duration::from_secs(20);
    let result = compute_reset_after(Some(&oldest), now, window);
    assert_eq!(result, 1);
}

#[test]
fn compute_reset_after_plus_one_rounds_up() {
    // Verify `+ 1` is applied: 59.9s remaining → 60s, not 59s
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // oldest is 1500ms ago
    let oldest = now - Duration::from_millis(1500);
    let result = compute_reset_after(Some(&oldest), now, window);
    // expires_at = oldest + 60s = now + 58.5s
    // (58.5s).as_secs() = 58, +1 = 59
    assert_eq!(result, 59);
}

// -----------------------------------------------------------------------
// evict_expired unit tests (kills the function deletion mutant)
// -----------------------------------------------------------------------

#[test]
fn evict_expired_removes_old_timestamps() {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    let mut timestamps = VecDeque::new();
    timestamps.push_back(now - Duration::from_secs(120));
    timestamps.push_back(now - Duration::from_secs(90));
    timestamps.push_back(now - Duration::from_secs(30));

    evict_expired(&mut timestamps, now, window);

    assert_eq!(
        timestamps.len(),
        1,
        "only the recent timestamp should remain"
    );
    // The remaining timestamp should be the one from 30s ago
    let remaining = *timestamps.front().unwrap();
    assert!(remaining > now - Duration::from_secs(60));
}

#[test]
fn evict_expired_keeps_all_within_window() {
    let now = Instant::now();
    let window = Duration::from_secs(60);
    let mut timestamps = VecDeque::new();
    timestamps.push_back(now - Duration::from_secs(30));
    timestamps.push_back(now - Duration::from_secs(10));
    timestamps.push_back(now);

    evict_expired(&mut timestamps, now, window);

    assert_eq!(timestamps.len(), 3, "all timestamps should remain");
}

#[test]
fn evict_expired_removes_all_when_all_old() {
    let now = Instant::now();
    let window = Duration::from_secs(10);
    let mut timestamps = VecDeque::new();
    timestamps.push_back(now - Duration::from_secs(100));
    timestamps.push_back(now - Duration::from_secs(50));

    evict_expired(&mut timestamps, now, window);

    assert!(timestamps.is_empty(), "all timestamps should be evicted");
}

// -----------------------------------------------------------------------
// cleanup retains non-empty entries (kills `delete !` mutation)
// -----------------------------------------------------------------------

#[test]
fn cleanup_retains_active_entries() {
    let limiter = SlidingWindowLimiter::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let tier = strict_tier();

    // Record a request (recent, within any window)
    limiter.check_and_record(ip, RateLimitTier::Strict, &tier);

    // Cleanup with the same window — entry is still active
    limiter.cleanup(Duration::from_secs(60));

    let state = limiter.state.lock().unwrap();
    assert!(
        state.contains_key(&(ip, RateLimitTier::Strict)),
        "active entry should be retained after cleanup"
    );
}
