use anyhow::anyhow;

use super::AppConfig;

pub(super) fn validate_db_pool(config: &AppConfig) -> anyhow::Result<()> {
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

pub(super) fn validate_signing_key_secret(secret: &str) -> anyhow::Result<()> {
    if secret.len() < 16 {
        return Err(anyhow!(
            "SERVER_SIGNING_KEY_SECRET must be at least 16 bytes"
        ));
    }
    Ok(())
}

pub(super) fn validate_rate_limit(config: &AppConfig) -> anyhow::Result<()> {
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

pub(super) fn validate_device_jwt_validity(config: &AppConfig) -> anyhow::Result<()> {
    if config.device_jwt_validity_seconds == 0 {
        return Err(anyhow!(
            "SERVER_DEVICE_JWT_VALIDITY_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

pub(super) fn validate_pairing_config(config: &AppConfig) -> anyhow::Result<()> {
    if config.pairing_jwt_validity_seconds == 0 {
        return Err(anyhow!(
            "SERVER_PAIRING_JWT_VALIDITY_SECONDS must be greater than 0"
        ));
    }
    if config.client_jwt_validity_seconds == 0 {
        return Err(anyhow!(
            "SERVER_CLIENT_JWT_VALIDITY_SECONDS must be greater than 0"
        ));
    }
    if config.unconsumed_pairing_limit <= 0 {
        return Err(anyhow!(
            "SERVER_UNCONSUMED_PAIRING_LIMIT must be greater than 0"
        ));
    }
    Ok(())
}

pub(super) fn validate_request_jwt_validity(config: &AppConfig) -> anyhow::Result<()> {
    if config.request_jwt_validity_seconds == 0 {
        return Err(anyhow!(
            "SERVER_REQUEST_JWT_VALIDITY_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

pub(super) fn validate_cleanup_interval(config: &AppConfig) -> anyhow::Result<()> {
    if config.cleanup_interval_seconds == 0 {
        return Err(anyhow!(
            "SERVER_CLEANUP_INTERVAL_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}

/// Maximum allowed value for duration configuration fields (~100 years).
const MAX_DURATION_SECONDS: u64 = 3_153_600_000;

pub(super) fn validate_duration_upper_bounds(config: &AppConfig) -> anyhow::Result<()> {
    let checks: &[(&str, u64)] = &[
        (
            "SERVER_CLEANUP_INTERVAL_SECONDS",
            config.cleanup_interval_seconds,
        ),
        (
            "SERVER_DEVICE_JWT_VALIDITY_SECONDS",
            config.device_jwt_validity_seconds,
        ),
        (
            "SERVER_CLIENT_JWT_VALIDITY_SECONDS",
            config.client_jwt_validity_seconds,
        ),
        (
            "SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS",
            config.audit_log_approved_retention_seconds,
        ),
        (
            "SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS",
            config.audit_log_denied_retention_seconds,
        ),
        (
            "SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS",
            config.audit_log_conflict_retention_seconds,
        ),
    ];
    for &(name, value) in checks {
        if value > MAX_DURATION_SECONDS {
            return Err(anyhow!(
                "{name} ({value}) exceeds maximum allowed value ({MAX_DURATION_SECONDS})"
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_unpaired_client_max_age(config: &AppConfig) -> anyhow::Result<()> {
    if config.unpaired_client_max_age_hours == 0 {
        return Err(anyhow!(
            "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS must be greater than 0"
        ));
    }
    // Convert to seconds and check upper bound.
    let seconds = config
        .unpaired_client_max_age_hours
        .checked_mul(3600)
        .ok_or_else(|| {
            anyhow!(
                "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS ({}) overflows when converted to seconds",
                config.unpaired_client_max_age_hours,
            )
        })?;
    if seconds > MAX_DURATION_SECONDS {
        return Err(anyhow!(
            "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS ({}) exceeds maximum allowed value ({} hours)",
            config.unpaired_client_max_age_hours,
            MAX_DURATION_SECONDS / 3600,
        ));
    }
    Ok(())
}

pub(super) fn validate_audit_log_retention(config: &AppConfig) -> anyhow::Result<()> {
    if config.audit_log_approved_retention_seconds == 0 {
        return Err(anyhow!(
            "SERVER_AUDIT_LOG_APPROVED_RETENTION_SECONDS must be greater than 0"
        ));
    }
    if config.audit_log_denied_retention_seconds == 0 {
        return Err(anyhow!(
            "SERVER_AUDIT_LOG_DENIED_RETENTION_SECONDS must be greater than 0"
        ));
    }
    if config.audit_log_conflict_retention_seconds == 0 {
        return Err(anyhow!(
            "SERVER_AUDIT_LOG_CONFLICT_RETENTION_SECONDS must be greater than 0"
        ));
    }
    Ok(())
}
