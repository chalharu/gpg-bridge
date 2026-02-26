use anyhow::anyhow;

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

fn validate_db_pool(config: &AppConfig) -> anyhow::Result<()> {
    if config.db_min_connections > config.db_max_connections {
        return Err(anyhow!(
            "SERVER_DB_MIN_CONNECTIONS ({}) must be less than or equal to SERVER_DB_MAX_CONNECTIONS ({})",
            config.db_min_connections,
            config.db_max_connections
        ));
    }
    if config.db_acquire_timeout_seconds == 0 {
        return Err(anyhow!(
            "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

fn validate_signing_key_secret(secret: &str) -> anyhow::Result<()> {
    if secret.len() < 16 {
        return Err(anyhow!(
            "SERVER_SIGNING_KEY_SECRET must be at least 16 bytes"
        ));
    }
    Ok(())
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

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
        };

        validate_db_pool(&config)?;
        validate_signing_key_secret(&config.signing_key_secret)?;
        validate_rate_limit(&config)?;
        validate_device_jwt_validity(&config)?;

        Ok(config)
    }
}

fn validate_rate_limit(config: &AppConfig) -> anyhow::Result<()> {
    if config.rate_limit_strict_quota == 0 {
        return Err(anyhow!(
            "SERVER_RATE_LIMIT_STRICT_QUOTA must be greater than 0"
        ));
    }
    if config.rate_limit_strict_window_seconds == 0 {
        return Err(anyhow!(
            "SERVER_RATE_LIMIT_STRICT_WINDOW_SECONDS must be greater than 0"
        ));
    }
    if config.rate_limit_standard_quota == 0 {
        return Err(anyhow!(
            "SERVER_RATE_LIMIT_STANDARD_QUOTA must be greater than 0"
        ));
    }
    if config.rate_limit_standard_window_seconds == 0 {
        return Err(anyhow!(
            "SERVER_RATE_LIMIT_STANDARD_WINDOW_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

fn validate_device_jwt_validity(config: &AppConfig) -> anyhow::Result<()> {
    if config.device_jwt_validity_seconds == 0 {
        return Err(anyhow!(
            "SERVER_DEVICE_JWT_VALIDITY_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
