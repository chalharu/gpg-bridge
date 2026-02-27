use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use super::config::SseConnectionConfig;

/// Tracks concurrent SSE connections per IP and per logical key.
#[derive(Debug, Clone)]
pub struct SseConnectionTracker {
    inner: Arc<Mutex<TrackerState>>,
    config: SseConnectionConfig,
}

#[derive(Debug)]
struct TrackerState {
    per_ip: HashMap<IpAddr, u32>,
    per_key: HashMap<String, u32>,
}

/// RAII guard that decrements connection counts on drop.
pub struct SseConnectionGuard {
    inner: Arc<Mutex<TrackerState>>,
    ip: IpAddr,
    key: String,
}

impl SseConnectionTracker {
    pub fn new(config: SseConnectionConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerState {
                per_ip: HashMap::new(),
                per_key: HashMap::new(),
            })),
            config,
        }
    }

    /// Try to acquire a connection slot. Returns a guard on success,
    /// or an error variant indicating which limit was exceeded.
    pub fn try_acquire(&self, ip: IpAddr, key: String) -> Result<SseConnectionGuard, SseRejection> {
        let mut state = self.inner.lock().expect("sse tracker lock poisoned");

        let ip_count = state.per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.config.max_per_ip {
            return Err(SseRejection::IpLimitExceeded {
                current: ip_count,
                max: self.config.max_per_ip,
            });
        }

        let key_count = state.per_key.get(&key).copied().unwrap_or(0);
        if key_count >= self.config.max_per_key {
            return Err(SseRejection::KeyLimitExceeded {
                current: key_count,
                max: self.config.max_per_key,
            });
        }

        *state.per_ip.entry(ip).or_insert(0) += 1;
        *state.per_key.entry(key.clone()).or_insert(0) += 1;

        Ok(SseConnectionGuard {
            inner: Arc::clone(&self.inner),
            ip,
            key,
        })
    }

    /// Current connection count for an IP (for testing/observability).
    pub fn ip_connection_count(&self, ip: IpAddr) -> u32 {
        let state = self.inner.lock().expect("sse tracker lock poisoned");
        state.per_ip.get(&ip).copied().unwrap_or(0)
    }

    /// Current connection count for a key (for testing/observability).
    pub fn key_connection_count(&self, key: &str) -> u32 {
        let state = self.inner.lock().expect("sse tracker lock poisoned");
        state.per_key.get(key).copied().unwrap_or(0)
    }
}

/// Reason an SSE connection was rejected.
#[derive(Debug, Clone)]
pub enum SseRejection {
    IpLimitExceeded { current: u32, max: u32 },
    KeyLimitExceeded { current: u32, max: u32 },
}

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.inner.lock().expect("sse tracker lock poisoned");
        decrement_counter(&mut state.per_ip, &self.ip);
        decrement_key_counter(&mut state.per_key, &self.key);
    }
}

fn decrement_counter(map: &mut HashMap<IpAddr, u32>, key: &IpAddr) {
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(key);
        }
    }
}

fn decrement_key_counter(map: &mut HashMap<String, u32>, key: &str) {
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SseConnectionConfig {
        SseConnectionConfig {
            max_per_ip: 2,
            max_per_key: 1,
        }
    }

    #[test]
    fn acquires_within_ip_limit() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let _g1 = tracker.try_acquire(ip, "key-a".into()).unwrap();
        let _g2 = tracker.try_acquire(ip, "key-b".into()).unwrap();

        assert_eq!(tracker.ip_connection_count(ip), 2);
    }

    #[test]
    fn rejects_over_ip_limit() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let _g1 = tracker.try_acquire(ip, "key-a".into()).unwrap();
        let _g2 = tracker.try_acquire(ip, "key-b".into()).unwrap();
        let result = tracker.try_acquire(ip, "key-c".into());

        assert!(matches!(result, Err(SseRejection::IpLimitExceeded { .. })));
    }

    #[test]
    fn rejects_duplicate_key() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let _g1 = tracker.try_acquire(ip, "key-a".into()).unwrap();
        let result = tracker.try_acquire(ip, "key-a".into());

        assert!(matches!(result, Err(SseRejection::KeyLimitExceeded { .. })));
    }

    #[test]
    fn guard_drop_decrements_counters() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        {
            let _g = tracker.try_acquire(ip, "key-a".into()).unwrap();
            assert_eq!(tracker.ip_connection_count(ip), 1);
            assert_eq!(tracker.key_connection_count("key-a"), 1);
        }

        assert_eq!(tracker.ip_connection_count(ip), 0);
        assert_eq!(tracker.key_connection_count("key-a"), 0);
    }

    #[test]
    fn different_ips_are_independent() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let _g1 = tracker.try_acquire(ip1, "key-a".into()).unwrap();
        let _g2 = tracker.try_acquire(ip1, "key-b".into()).unwrap();

        // ip2 should still be able to connect
        let _g3 = tracker.try_acquire(ip2, "key-c".into()).unwrap();
        assert_eq!(tracker.ip_connection_count(ip2), 1);
    }

    #[test]
    fn slot_available_after_guard_drop() {
        let tracker = SseConnectionTracker::new(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let g1 = tracker.try_acquire(ip, "key-a".into()).unwrap();
        let _g2 = tracker.try_acquire(ip, "key-b".into()).unwrap();
        drop(g1);

        let _g3 = tracker.try_acquire(ip, "key-c".into()).unwrap();
        assert_eq!(tracker.ip_connection_count(ip), 2);
    }
}
