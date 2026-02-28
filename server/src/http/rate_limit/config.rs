use crate::config::AppConfig;

/// Rate limit tier configuration.
#[derive(Debug, Clone)]
pub struct TierConfig {
    /// Maximum number of requests allowed within the window.
    pub quota: u32,
    /// Window duration in seconds.
    pub window_seconds: u64,
}

/// SSE concurrent connection limits.
#[derive(Debug, Clone)]
pub struct SseConnectionConfig {
    /// Maximum concurrent SSE connections per IP.
    pub max_per_ip: u32,
    /// Maximum concurrent SSE connections per logical key
    /// (e.g. pairing_jwt subject or request_id).
    pub max_per_key: u32,
}

/// Top-level rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub strict: TierConfig,
    pub standard: TierConfig,
    pub sse: SseConnectionConfig,
}

impl RateLimitConfig {
    /// Build from application configuration.
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            strict: TierConfig {
                quota: config.rate_limit_strict_quota,
                window_seconds: config.rate_limit_strict_window_seconds,
            },
            standard: TierConfig {
                quota: config.rate_limit_standard_quota,
                window_seconds: config.rate_limit_standard_window_seconds,
            },
            sse: SseConnectionConfig {
                max_per_ip: config.rate_limit_sse_max_per_ip,
                max_per_key: config.rate_limit_sse_max_per_key,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_config_is_cloneable() {
        let cfg = RateLimitConfig {
            strict: TierConfig {
                quota: 10,
                window_seconds: 60,
            },
            standard: TierConfig {
                quota: 60,
                window_seconds: 60,
            },
            sse: SseConnectionConfig {
                max_per_ip: 20,
                max_per_key: 1,
            },
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.strict.quota, 10);
        assert_eq!(cloned.standard.quota, 60);
        assert_eq!(cloned.sse.max_per_ip, 20);
        assert_eq!(cloned.sse.max_per_key, 1);
    }

    #[test]
    fn from_app_config_maps_all_fields() {
        let app = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 8080,
            database_url: "sqlite::memory:".to_owned(),
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 30,
            log_level: "info".to_owned(),
            log_format: "json".to_owned(),
            signing_key_secret: "test-secret-that-is-long-enough".to_owned(),
            base_url: "http://localhost:8080".to_owned(),
            device_jwt_validity_seconds: 31_536_000,
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            rate_limit_strict_quota: 5,
            rate_limit_strict_window_seconds: 30,
            rate_limit_standard_quota: 100,
            rate_limit_standard_window_seconds: 120,
            rate_limit_sse_max_per_ip: 10,
            rate_limit_sse_max_per_key: 3,
        };

        let cfg = RateLimitConfig::from_app_config(&app);

        assert_eq!(cfg.strict.quota, 5);
        assert_eq!(cfg.strict.window_seconds, 30);
        assert_eq!(cfg.standard.quota, 100);
        assert_eq!(cfg.standard.window_seconds, 120);
        assert_eq!(cfg.sse.max_per_ip, 10);
        assert_eq!(cfg.sse.max_per_key, 3);
    }

    #[test]
    fn tier_config_debug_and_clone() {
        let tier = TierConfig {
            quota: 42,
            window_seconds: 90,
        };
        let cloned = tier.clone();
        assert_eq!(cloned.quota, 42);
        assert_eq!(cloned.window_seconds, 90);
        // Debug is derived
        let debug = format!("{tier:?}");
        assert!(debug.contains("42"));
    }

    #[test]
    fn sse_connection_config_debug_and_clone() {
        let sse = SseConnectionConfig {
            max_per_ip: 15,
            max_per_key: 2,
        };
        let cloned = sse.clone();
        assert_eq!(cloned.max_per_ip, 15);
        assert_eq!(cloned.max_per_key, 2);
        let debug = format!("{sse:?}");
        assert!(debug.contains("15"));
    }
}
