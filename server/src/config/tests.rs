use std::collections::HashMap;

use super::*;

const DEFAULT_DATABASE_URL: &str = "postgres://localhost:5432/gpg_bridge";
const SQLITE_MEMORY_DATABASE_URL: &str = "sqlite::memory:";
const DEFAULT_SIGNING_KEY_SECRET: &str = "test-secret-key!";

fn config_from_env(entries: &[(&str, &str)]) -> anyhow::Result<AppConfig> {
    let env = entries.iter().copied().collect::<HashMap<_, _>>();
    AppConfig::from_lookup(&|key| env.get(key).map(|value| (*value).to_owned()))
}

fn config_with_required_env(overrides: &[(&str, &str)]) -> anyhow::Result<AppConfig> {
    let mut env = HashMap::from([
        ("SERVER_DATABASE_URL", DEFAULT_DATABASE_URL),
        ("SERVER_SIGNING_KEY_SECRET", DEFAULT_SIGNING_KEY_SECRET),
    ]);
    env.extend(overrides.iter().copied());

    AppConfig::from_lookup(&|key| env.get(key).map(|value| (*value).to_owned()))
}

fn assert_invalid_config(overrides: &[(&str, &str)], expected_message: &str) {
    let error = config_with_required_env(overrides).unwrap_err();
    assert!(
        error.to_string().contains(expected_message),
        "expected error message to mention {expected_message}, got {error}"
    );
}

#[test]
fn config_uses_defaults_and_required_values() {
    let config = config_with_required_env(&[]).unwrap();

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
    let result = config_from_env(&[]);

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
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_DB_MAX_CONNECTIONS", "2"),
            ("SERVER_DB_MIN_CONNECTIONS", "3"),
        ],
        "SERVER_DB_MIN_CONNECTIONS",
    );
}

#[test]
fn config_rejects_short_signing_key_secret() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_SIGNING_KEY_SECRET", "short"),
        ],
        "at least 16 bytes",
    );
}

#[test]
fn config_rejects_missing_signing_key_secret() {
    let result = config_from_env(&[("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL)]);

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
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_DB_ACQUIRE_TIMEOUT_SECONDS", "0"),
        ],
        "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS",
    );
}

#[test]
fn config_rejects_zero_strict_quota() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_RATE_LIMIT_STRICT_QUOTA", "0"),
        ],
        "SERVER_RATE_LIMIT_STRICT_QUOTA",
    );
}

#[test]
fn config_rejects_zero_standard_window() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS", "0"),
        ],
        "SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS",
    );
}

#[test]
fn config_rejects_zero_cleanup_interval() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_CLEANUP_INTERVAL_SECONDS", "0"),
        ],
        "SERVER_CLEANUP_INTERVAL_SECONDS",
    );
}

#[test]
fn config_rejects_duration_exceeding_upper_bound() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_DEVICE_JWT_VALIDITY_SECONDS", "9999999999999"),
        ],
        "exceeds maximum",
    );
}

#[test]
fn config_rejects_zero_unpaired_client_max_age() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS", "0"),
        ],
        "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS",
    );
}

#[test]
fn config_rejects_zero_audit_log_approved_retention() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS", "0"),
        ],
        "SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS",
    );
}

#[test]
fn config_rejects_zero_audit_log_denied_retention() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS", "0"),
        ],
        "SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS",
    );
}

#[test]
fn config_rejects_zero_audit_log_conflict_retention() {
    assert_invalid_config(
        &[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            ("SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS", "0"),
        ],
        "SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS",
    );
}

#[test]
fn config_accepts_min_connections_equal_to_max() {
    let result = config_with_required_env(&[
        ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
        ("SERVER_DB_MAX_CONNECTIONS", "5"),
        ("SERVER_DB_MIN_CONNECTIONS", "5"),
    ]);

    assert!(result.is_ok(), "min == max should be accepted");
    let config = result.unwrap();
    assert_eq!(config.db_min_connections, 5);
    assert_eq!(config.db_max_connections, 5);
}

#[test]
fn config_accepts_strict_quota_of_one() {
    let result = config_with_required_env(&[
        ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
        ("SERVER_RATE_LIMIT_STRICT_QUOTA", "1"),
    ]);

    assert!(result.is_ok(), "quota == 1 should be accepted");
    let config = result.unwrap();
    assert_eq!(config.rate_limit_strict_quota, 1);
}

#[test]
fn config_accepts_standard_quota_of_one() {
    let result = config_with_required_env(&[
        ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
        ("SERVER_RATE_LIMIT_STANDARD_QUOTA", "1"),
    ]);

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
        let result = config_with_required_env(&[
            ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
            (env_key, "0"),
        ]);

        assert!(result.is_err(), "{env_key} should be rejected when zero");
        assert!(
            result.unwrap_err().to_string().contains(expected_message),
            "expected error message to mention {expected_message}"
        );
    }
}

#[test]
fn config_rejects_unpaired_client_max_age_overflow() {
    let overflow = u64::MAX.to_string();
    let result = config_with_required_env(&[
        ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
        ("SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS", overflow.as_str()),
    ]);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("overflows when converted to seconds")
    );
}

#[test]
fn config_rejects_unpaired_client_max_age_exceeding_upper_bound() {
    let result = config_with_required_env(&[
        ("SERVER_DATABASE_URL", SQLITE_MEMORY_DATABASE_URL),
        ("SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS", "876001"),
    ]);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum allowed value")
    );
}
