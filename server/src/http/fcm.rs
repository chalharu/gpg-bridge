use async_trait::async_trait;

/// Validates FCM device tokens.
#[async_trait]
pub trait FcmValidator: Send + Sync + std::fmt::Debug {
    async fn validate_token(&self, token: &str) -> anyhow::Result<bool>;
}

/// No-op validator that always returns `Ok(true)`.
#[derive(Debug, Clone)]
pub struct NoopFcmValidator;

#[async_trait]
impl FcmValidator for NoopFcmValidator {
    async fn validate_token(&self, _token: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_validator_always_returns_true() {
        let validator = NoopFcmValidator;
        assert!(validator.validate_token("any-token").await.unwrap());
    }
}
