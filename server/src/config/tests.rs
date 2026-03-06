use super::*;

#[test]
fn config_uses_defaults_and_required_values() {
    let config = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("postgres://localhost:5432/gpg_bridge".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        _ => None,
    })
    .unwrap();

    assert_eq!(config.server_host, "127.0.0.1");
    assert_eq!(config.server_port, 3000);
    assert_eq!(config.log_level, "info");
    assert_eq!(config.log_format, "plain");
    assert_eq!(config.database_url, "postgres://localhost:5432/gpg_bridge");
    assert_eq!(config.db_max_connections, 20);
    assert_eq!(config.db_min_connections, 1);
    assert_eq!(config.db_acquire_timeout_seconds, 5);
    assert_eq!(config.rate_limit_strict_quota, 10);
    assert_eq!(config.rate_limit_strict_window_seconds, 60);
    assert_eq!(config.rate_limit_standard_quota, 60);
    assert_eq!(config.rate_limit_standard_window_seconds, 60);
    assert_eq!(config.rate_limit_sse_max_per_ip, 20);
    assert_eq!(config.rate_limit_sse_max_per_key, 1);
    assert_eq!(config.device_jwt_validity_seconds, 31_536_000);
    assert_eq!(config.pairing_jwt_validity_seconds, 300);
    assert_eq!(config.client_jwt_validity_seconds, 31_536_000);
    assert_eq!(config.request_jwt_validity_seconds, 300);
    assert_eq!(config.unconsumed_pairing_limit, 100);
    assert_eq!(config.cleanup_interval_seconds, 60);
    assert_eq!(config.unpaired_client_max_age_hours, 24);
    assert_eq!(config.audit_log_approved_retention_seconds, 31_536_000);
    assert_eq!(config.audit_log_denied_retention_seconds, 15_768_000);
    assert_eq!(config.audit_log_conflict_retention_seconds, 7_884_000);
}

#[test]
fn config_returns_error_when_required_env_is_missing() {
    let result = AppConfig::from_lookup(&|_| None);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_DATABASE_URL")
    );
}

#[test]
fn detect_database_kind_supports_postgres() {
    let kind = detect_database_kind("postgres://localhost:5432/gpg_bridge").unwrap();
    assert_eq!(kind, DatabaseKind::Postgres);
}

#[test]
fn detect_database_kind_supports_sqlite() {
    let kind = detect_database_kind("sqlite://tmp/test.db").unwrap();
    assert_eq!(kind, DatabaseKind::Sqlite);
}

#[test]
fn detect_database_kind_rejects_unknown_scheme() {
    let result = detect_database_kind("mysql://localhost:3306/gpg_bridge");
    assert!(result.is_err());
}

#[test]
fn config_rejects_min_connections_larger_than_max() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_DB_MAX_CONNECTIONS" => Some("2".to_owned()),
        "SERVER_DB_MIN_CONNECTIONS" => Some("3".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_DB_MIN_CONNECTIONS")
    );
}

#[test]
fn config_rejects_short_signing_key_secret() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("short".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("at least 16 bytes")
    );
}

#[test]
fn config_rejects_missing_signing_key_secret() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_SIGNING_KEY_SECRET")
    );
}

#[test]
fn config_rejects_zero_acquire_timeout() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_DB_ACQUIRE_TIMEOUT_SECONDS")
    );
}

#[test]
fn config_rejects_zero_strict_quota() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_RATE_LIMIT_STRICT_QUOTA" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_RATE_LIMIT_STRICT_QUOTA")
    );
}

#[test]
fn config_rejects_zero_standard_window() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS")
    );
}

#[test]
fn config_rejects_zero_cleanup_interval() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_CLEANUP_INTERVAL_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_CLEANUP_INTERVAL_SECONDS")
    );
}

#[test]
fn config_rejects_duration_exceeding_upper_bound() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_DEVICE_JWT_VALIDITY_SECONDS" => Some("9999999999999".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
}

#[test]
fn config_rejects_zero_unpaired_client_max_age() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS")
    );
}

#[test]
fn config_rejects_zero_audit_log_approved_retention() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS")
    );
}

#[test]
fn config_rejects_zero_audit_log_denied_retention() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS")
    );
}

#[test]
fn config_rejects_zero_audit_log_conflict_retention() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS" => Some("0".to_owned()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS")
    );
}

#[test]
fn config_accepts_min_connections_equal_to_max() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_DB_MAX_CONNECTIONS" => Some("5".to_owned()),
        "SERVER_DB_MIN_CONNECTIONS" => Some("5".to_owned()),
        _ => None,
    });

    assert!(result.is_ok(), "min == max should be accepted");
    let config = result.unwrap();
    assert_eq!(config.db_min_connections, 5);
    assert_eq!(config.db_max_connections, 5);
}

#[test]
fn config_accepts_strict_quota_of_one() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_RATE_LIMIT_STRICT_QUOTA" => Some("1".to_owned()),
        _ => None,
    });

    assert!(result.is_ok(), "quota == 1 should be accepted");
    let config = result.unwrap();
    assert_eq!(config.rate_limit_strict_quota, 1);
}

#[test]
fn config_accepts_standard_quota_of_one() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_RATE_LIMIT_STANDARD_QUOTA" => Some("1".to_owned()),
        _ => None,
    });

    assert!(result.is_ok(), "standard quota == 1 should be accepted");
    let config = result.unwrap();
    assert_eq!(config.rate_limit_standard_quota, 1);
}

#[test]
fn config_rejects_zero_values_for_remaining_validation_guards() {
    let cases = [
        (
            "SERVER_RATE_LIMIT_STRICT_WINDOW_SECONDS",
            "SERVER_RATE_LIMIT_STRICT_WINDOW_SECONDS",
        ),
        (
            "SERVER_RATE_LIMIT_STANDARD_QUOTA",
            "SERVER_RATE_LIMIT_STANDARD_QUOTA",
        ),
        (
            "SERVER_DEVICE_JWT_VALIDITY_SECONDS",
            "SERVER_DEVICE_JWT_VALIDITY_SECONDS",
        ),
        (
            "SERVER_PAIRING_JWT_VALIDITY_SECONDS",
            "SERVER_PAIRING_JWT_VALIDITY_SECONDS",
        ),
        (
            "SERVER_CLIENT_JWT_VALIDITY_SECONDS",
            "SERVER_CLIENT_JWT_VALIDITY_SECONDS",
        ),
        (
            "SERVER_REQUEST_JWT_VALIDITY_SECONDS",
            "SERVER_REQUEST_JWT_VALIDITY_SECONDS",
        ),
        (
            "SERVER_UNCONSUMED_PAIRING_LIMIT",
            "SERVER_UNCONSUMED_PAIRING_LIMIT",
        ),
    ];

    for (env_key, expected_message) in cases {
        let result = AppConfig::from_lookup(&|key| match key {
            "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
            "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
            k if k == env_key => Some("0".to_owned()),
            _ => None,
        });

        assert!(result.is_err(), "{env_key} should be rejected when zero");
        assert!(
            result.unwrap_err().to_string().contains(expected_message),
            "expected error message to mention {expected_message}"
        );
    }
}

#[test]
fn config_rejects_unpaired_client_max_age_overflow() {
    let result = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS" => Some(u64::MAX.to_string()),
        _ => None,
    });

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("overflows when converted to seconds")
    );
}
