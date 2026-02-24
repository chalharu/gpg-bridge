use anyhow::{Context, anyhow};

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

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let server_host = lookup("SERVER_HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
        let server_port_raw = lookup("SERVER_PORT").unwrap_or_else(|| "3000".to_owned());
        let server_port: u16 = server_port_raw
            .parse()
            .with_context(|| format!("SERVER_PORT must be a valid u16, got '{server_port_raw}'"))?;

        let database_url = lookup("SERVER_DATABASE_URL")
            .ok_or_else(|| anyhow!("missing required environment variable: SERVER_DATABASE_URL"))?;

        let db_max_connections_raw =
            lookup("SERVER_DB_MAX_CONNECTIONS").unwrap_or_else(|| "20".to_owned());
        let db_max_connections: u32 = db_max_connections_raw.parse().with_context(|| {
            format!("SERVER_DB_MAX_CONNECTIONS must be a valid u32, got '{db_max_connections_raw}'")
        })?;

        let db_min_connections_raw =
            lookup("SERVER_DB_MIN_CONNECTIONS").unwrap_or_else(|| "1".to_owned());
        let db_min_connections: u32 = db_min_connections_raw.parse().with_context(|| {
            format!("SERVER_DB_MIN_CONNECTIONS must be a valid u32, got '{db_min_connections_raw}'")
        })?;

        let db_acquire_timeout_seconds_raw =
            lookup("SERVER_DB_ACQUIRE_TIMEOUT_SECONDS").unwrap_or_else(|| "5".to_owned());
        let db_acquire_timeout_seconds: u64 = db_acquire_timeout_seconds_raw.parse().with_context(|| {
            format!(
                "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS must be a valid u64, got '{db_acquire_timeout_seconds_raw}'"
            )
        })?;

        if db_min_connections > db_max_connections {
            return Err(anyhow!(
                "SERVER_DB_MIN_CONNECTIONS ({db_min_connections}) must be less than or equal to SERVER_DB_MAX_CONNECTIONS ({db_max_connections})"
            ));
        }

        if db_acquire_timeout_seconds == 0 {
            return Err(anyhow!(
                "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS must be greater than 0"
            ));
        }

        let log_level = lookup("SERVER_LOG_LEVEL").unwrap_or_else(|| "info".to_owned());
        let log_format = lookup("SERVER_LOG_FORMAT").unwrap_or_else(|| "plain".to_owned());

        let signing_key_secret = lookup("SERVER_SIGNING_KEY_SECRET").ok_or_else(|| {
            anyhow!("missing required environment variable: SERVER_SIGNING_KEY_SECRET")
        })?;

        if signing_key_secret.len() < 16 {
            return Err(anyhow!(
                "SERVER_SIGNING_KEY_SECRET must be at least 16 bytes"
            ));
        }

        Ok(Self {
            server_host,
            server_port,
            database_url,
            db_max_connections,
            db_min_connections,
            db_acquire_timeout_seconds,
            log_level,
            log_format,
            signing_key_secret,
        })
    }
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
}
