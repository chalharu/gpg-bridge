use crate::config::AppConfig;

mod audit_log_tests;
mod cleanup_tests;
mod client_pairing_tests;
mod client_tests;
mod fixture;
mod helpers;
mod infrastructure_tests;
mod jti_tests;
mod pairing_tests;
mod request_tests;
mod signing_key_tests;

fn sqlite_test_config() -> AppConfig {
    AppConfig {
        server_host: "127.0.0.1".to_owned(),
        server_port: 3000,
        database_url: "sqlite::memory:".to_owned(),
        db_max_connections: 4,
        db_min_connections: 1,
        db_acquire_timeout_seconds: 5,
        log_level: "info".to_owned(),
        log_format: "plain".to_owned(),
        signing_key_secret: "test-secret-key!".to_owned(),
        base_url: "http://localhost:3000".to_owned(),
        rate_limit_strict_quota: 10,
        rate_limit_strict_window_seconds: 60,
        rate_limit_standard_quota: 60,
        rate_limit_standard_window_seconds: 60,
        rate_limit_sse_max_per_ip: 20,
        rate_limit_sse_max_per_key: 1,
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_service_account_key_path: None,
        fcm_project_id: None,
        cleanup_interval_seconds: 60,
        unpaired_client_max_age_hours: 24,
        audit_log_approved_retention_seconds: 31_536_000,
        audit_log_denied_retention_seconds: 15_768_000,
        audit_log_conflict_retention_seconds: 7_884_000,
    }
}

/// Generate parameterized test wrappers for both SQLite and PostgreSQL.
macro_rules! repo_test {
    ($name:ident) => {
        mod $name {
            #[tokio::test]
            async fn sqlite() {
                let f = super::super::fixture::SqliteTestFixture::setup().await;
                super::$name(&f).await;
            }

            #[tokio::test]
            #[ignore = "requires embedded PostgreSQL"]
            async fn postgres() {
                let f = super::super::fixture::PostgresTestFixture::setup().await;
                super::$name(&f).await;
            }
        }
    };
}
// Make macro available to child modules.
pub(super) use repo_test;
