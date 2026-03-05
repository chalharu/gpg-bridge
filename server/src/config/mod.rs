mod validation;

use anyhow::anyhow;
use validation::{
    validate_audit_log_retention, validate_cleanup_interval, validate_db_pool,
    validate_device_jwt_validity, validate_duration_upper_bounds, validate_pairing_config,
    validate_rate_limit, validate_request_jwt_validity, validate_signing_key_secret,
    validate_unpaired_client_max_age,
};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub db_max_connections: u32,
    pub db_min_connections: u32,
    pub db_acquire_timeout_seconds: u64,
    pub log_level: String,
    pub log_format: String,
    pub signing_key_secret: String,
    pub base_url: String,
    pub rate_limit_strict_quota: u32,
    pub rate_limit_strict_window_seconds: u64,
    pub rate_limit_standard_quota: u32,
    pub rate_limit_standard_window_seconds: u64,
    pub rate_limit_sse_max_per_ip: u32,
    pub rate_limit_sse_max_per_key: u32,
    pub device_jwt_validity_seconds: u64,
    pub pairing_jwt_validity_seconds: u64,
    pub client_jwt_validity_seconds: u64,
    pub request_jwt_validity_seconds: u64,
    pub unconsumed_pairing_limit: i64,
    pub fcm_service_account_key_path: Option<String>,
    pub fcm_project_id: Option<String>,
    pub cleanup_interval_seconds: u64,
    pub unpaired_client_max_age_hours: u64,
    pub audit_log_approved_retention_seconds: u64,
    pub audit_log_denied_retention_seconds: u64,
    pub audit_log_conflict_retention_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Postgres,
    Sqlite,
}

pub fn detect_database_kind(database_url: &str) -> anyhow::Result<DatabaseKind> {
    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        return Ok(DatabaseKind::Postgres);
    }

    if database_url.starts_with("sqlite:") {
        return Ok(DatabaseKind::Sqlite);
    }

    Err(anyhow!(
        "unsupported SERVER_DATABASE_URL scheme. expected postgres://, postgresql://, or sqlite:, got '{database_url}'"
    ))
}

fn parse_env<T>(
    lookup: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: &str,
) -> anyhow::Result<T>
where
    T: std::str::FromStr,
{
    let raw = lookup(key).unwrap_or_else(|| default.to_owned());
    raw.parse::<T>().map_err(|_| {
        anyhow!(
            "{key} must be a valid {}, got '{raw}'",
            std::any::type_name::<T>()
        )
    })
}

fn require_env(lookup: &dyn Fn(&str) -> Option<String>, key: &str) -> anyhow::Result<String> {
    lookup(key).ok_or_else(|| anyhow!("missing required environment variable: {key}"))
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    // ci:max-method-lines 110
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let server_host = lookup("SERVER_HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
        let server_port: u16 = parse_env(lookup, "SERVER_PORT", "3000")?;
        let database_url = require_env(lookup, "SERVER_DATABASE_URL")?;
        let db_max_connections: u32 = parse_env(lookup, "SERVER_DB_MAX_CONNECTIONS", "20")?;
        let db_min_connections: u32 = parse_env(lookup, "SERVER_DB_MIN_CONNECTIONS", "1")?;
        let db_acquire_timeout_seconds: u64 =
            parse_env(lookup, "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS", "5")?;
        let log_level = lookup("SERVER_LOG_LEVEL").unwrap_or_else(|| "info".to_owned());
        let log_format = lookup("SERVER_LOG_FORMAT").unwrap_or_else(|| "plain".to_owned());
        let signing_key_secret = require_env(lookup, "SERVER_SIGNING_KEY_SECRET")?;
        let base_url = lookup("SERVER_BASE_URL")
            .unwrap_or_else(|| format!("http://{server_host}:{server_port}"));
        let rate_limit_strict_quota: u32 =
            parse_env(lookup, "SERVER_RATE_LIMIT_STRICT_QUOTA", "10")?;
        let rate_limit_strict_window_seconds: u64 =
            parse_env(lookup, "SERVER_RATE_LIMIT_STRICT_WINDOW_SECONDS", "60")?;
        let rate_limit_standard_quota: u32 =
            parse_env(lookup, "SERVER_RATE_LIMIT_STANDARD_QUOTA", "60")?;
        let rate_limit_standard_window_seconds: u64 =
            parse_env(lookup, "SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS", "60")?;
        let rate_limit_sse_max_per_ip: u32 =
            parse_env(lookup, "SERVER_RATE_LIMIT_SSE_MAX_PER_IP", "20")?;
        let rate_limit_sse_max_per_key: u32 =
            parse_env(lookup, "SERVER_RATE_LIMIT_SSE_MAX_PER_KEY", "1")?;
        let device_jwt_validity_seconds: u64 =
            parse_env(lookup, "SERVER_DEVICE_JWT_VALIDITY_SECONDS", "31536000")?;
        let pairing_jwt_validity_seconds: u64 =
            parse_env(lookup, "SERVER_PAIRING_JWT_VALIDITY_SECONDS", "300")?;
        let client_jwt_validity_seconds: u64 =
            parse_env(lookup, "SERVER_CLIENT_JWT_VALIDITY_SECONDS", "31536000")?;
        let request_jwt_validity_seconds: u64 =
            parse_env(lookup, "SERVER_REQUEST_JWT_VALIDITY_SECONDS", "300")?;
        let unconsumed_pairing_limit: i64 =
            parse_env(lookup, "SERVER_UNCONSUMED_PAIRING_LIMIT", "100")?;
        let fcm_service_account_key_path = lookup("SERVER_FCM_SERVICE_ACCOUNT_KEY_PATH");
        let fcm_project_id = lookup("SERVER_FCM_PROJECT_ID");
        let cleanup_interval_seconds: u64 =
            parse_env(lookup, "SERVER_CLEANUP_INTERVAL_SECONDS", "60")?;
        let unpaired_client_max_age_hours: u64 =
            parse_env(lookup, "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS", "24")?;
        let audit_log_approved_retention_seconds: u64 = parse_env(
            lookup,
            "SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS",
            "31536000",
        )?;
        let audit_log_denied_retention_seconds: u64 = parse_env(
            lookup,
            "SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS",
            "15768000",
        )?;
        let audit_log_conflict_retention_seconds: u64 = parse_env(
            lookup,
            "SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS",
            "7884000",
        )?;

        let config = Self {
            server_host,
            server_port,
            database_url,
            db_max_connections,
            db_min_connections,
            db_acquire_timeout_seconds,
            log_level,
            log_format,
            signing_key_secret,
            base_url,
            rate_limit_strict_quota,
            rate_limit_strict_window_seconds,
            rate_limit_standard_quota,
            rate_limit_standard_window_seconds,
            rate_limit_sse_max_per_ip,
            rate_limit_sse_max_per_key,
            device_jwt_validity_seconds,
            pairing_jwt_validity_seconds,
            client_jwt_validity_seconds,
            request_jwt_validity_seconds,
            unconsumed_pairing_limit,
            fcm_service_account_key_path,
            fcm_project_id,
            cleanup_interval_seconds,
            unpaired_client_max_age_hours,
            audit_log_approved_retention_seconds,
            audit_log_denied_retention_seconds,
            audit_log_conflict_retention_seconds,
        };

        validate_db_pool(&config)?;
        validate_signing_key_secret(&config.signing_key_secret)?;
        validate_rate_limit(&config)?;
        validate_device_jwt_validity(&config)?;
        validate_pairing_config(&config)?;
        validate_request_jwt_validity(&config)?;
        validate_cleanup_interval(&config)?;
        validate_duration_upper_bounds(&config)?;
        validate_unpaired_client_max_age(&config)?;
        validate_audit_log_retention(&config)?;

        Ok(config)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
