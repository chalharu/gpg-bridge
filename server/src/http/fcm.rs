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

/// Sends FCM data messages to devices.
#[async_trait]
pub trait FcmSender: Send + Sync + std::fmt::Debug {
    async fn send_data_message(
        &self,
        device_token: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<()>;
}

/// No-op sender that does nothing (for testing).
#[derive(Debug, Clone)]
pub struct NoopFcmSender;

#[async_trait]
impl FcmSender for NoopFcmSender {
    async fn send_data_message(
        &self,
        _device_token: &str,
        _data: &serde_json::Value,
    ) -> anyhow::Result<()> {
        Ok(())
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

    #[tokio::test]
    async fn noop_sender_succeeds() {
        let sender = NoopFcmSender;
        let data = serde_json::json!({"type": "sign_request"});
        sender.send_data_message("token", &data).await.unwrap();
    }
}
