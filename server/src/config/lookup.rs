use super::validation::{
    validate_audit_log_retention, validate_cleanup_interval, validate_db_pool,
    validate_device_jwt_validity, validate_duration_upper_bounds, validate_pairing_config,
    validate_rate_limit, validate_request_jwt_validity, validate_signing_key_secret,
    validate_unpaired_client_max_age,
};
use super::{AppConfig, parse_env, require_env};

pub(super) struct EnvLookup<'a> {
    lookup: &'a dyn Fn(&str) -> Option<String>,
}

impl<'a> EnvLookup<'a> {
    pub(super) fn new(lookup: &'a dyn Fn(&str) -> Option<String>) -> Self {
        Self { lookup }
    }

    pub(super) fn value(&self, key: &str) -> Option<String> {
        (self.lookup)(key)
    }

    pub(super) fn string(&self, key: &str, default: &str) -> String {
        self.value(key).unwrap_or_else(|| default.to_owned())
    }

    pub(super) fn parsed<T>(&self, key: &str, default: &str) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
    {
        parse_env(self.lookup, key, default)
    }

    pub(super) fn required(&self, key: &str) -> anyhow::Result<String> {
        require_env(self.lookup, key)
    }
}

pub(super) fn validate_config(config: &AppConfig) -> anyhow::Result<()> {
    validate_db_pool(config)?;
    validate_signing_key_secret(&config.signing_key_secret)?;
    validate_rate_limit(config)?;
    validate_device_jwt_validity(config)?;
    validate_pairing_config(config)?;
    validate_request_jwt_validity(config)?;
    validate_cleanup_interval(config)?;
    validate_duration_upper_bounds(config)?;
    validate_unpaired_client_max_age(config)?;
    validate_audit_log_retention(config)?;

    Ok(())
}
