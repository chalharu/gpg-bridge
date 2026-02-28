pub(crate) mod client;
pub(crate) mod helpers;
pub(crate) mod oauth2;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod test_helpers;

pub use client::FcmClient;

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

/// Build an `FcmClient` from a service account key file path and project ID.
pub fn build_fcm_client(key_path: &str, project_id: &str) -> anyhow::Result<FcmClient> {
    let key_json = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow::anyhow!("failed to read FCM key file '{key_path}': {e}"))?;
    let sa: oauth2::ServiceAccountKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("failed to parse FCM key file: {e}"))?;
    FcmClient::new(project_id.to_owned(), sa)
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

    #[test]
    fn build_fcm_client_from_valid_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_sa.json");
        let sa_json = serde_json::json!({
            "client_email": "test@proj.iam.gserviceaccount.com",
            "private_key": include_str!("../../../test_fixtures/fake_rsa_key.pem"),
            "token_uri": "https://oauth2.googleapis.com/token"
        });
        std::fs::write(&path, sa_json.to_string()).unwrap();
        let result = build_fcm_client(path.to_str().unwrap(), "test-proj");
        assert!(result.is_ok());
    }

    #[test]
    fn build_fcm_client_missing_file() {
        let result = build_fcm_client("/nonexistent/path.json", "proj");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to read"));
    }

    #[test]
    fn build_fcm_client_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_sa.json");
        std::fs::write(&path, "not valid json").unwrap();
        let result = build_fcm_client(path.to_str().unwrap(), "proj");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to parse"));
    }
}
