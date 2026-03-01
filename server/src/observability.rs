use anyhow::{Context, anyhow};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::config::AppConfig;

pub fn init_tracing(config: &AppConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(config.log_level.clone()))
        .context("failed to initialize tracing env filter")?;

    let format = config.log_format.to_ascii_lowercase();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE);

    match format.as_str() {
        "plain" => builder
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))?,
        "json" => builder
            .json()
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))?,
        _ => {
            return Err(anyhow!(
                "SERVER_LOG_FORMAT must be either 'plain' or 'json', got '{format}'"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    #[test]
    fn init_tracing_rejects_invalid_log_format() {
        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "postgres://localhost:5432/gpg_bridge".to_owned(),
            db_max_connections: 20,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "invalid".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
            base_url: "http://localhost:3000".to_owned(),
            device_jwt_validity_seconds: 31_536_000,
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            fcm_service_account_key_path: None,
            fcm_project_id: None,
            cleanup_interval_seconds: 60,
            unpaired_client_max_age_hours: 24,
            rate_limit_strict_quota: 10,
            rate_limit_strict_window_seconds: 60,
            rate_limit_standard_quota: 60,
            rate_limit_standard_window_seconds: 60,
            rate_limit_sse_max_per_ip: 20,
            rate_limit_sse_max_per_key: 1,
            audit_log_approved_retention_seconds: 31_536_000,
            audit_log_denied_retention_seconds: 15_768_000,
            audit_log_conflict_retention_seconds: 7_884_000,
        };

        let result = init_tracing(&config);
        assert!(result.is_err());
    }
}
