use anyhow::{Context, anyhow};
use async_trait::async_trait;
use tracing::warn;

use super::helpers::{convert_to_string_map, extract_fcm_error_code};
use super::oauth2::{OAuth2TokenManager, ServiceAccountKey};
use super::{FcmSender, FcmValidator};

/// Real FCM HTTP v1 API client.
#[derive(Debug)]
pub struct FcmClient {
    project_id: String,
    http_client: reqwest::Client,
    token_manager: OAuth2TokenManager,
    fcm_base_url: String,
}

impl FcmClient {
    pub fn new(project_id: String, service_account: ServiceAccountKey) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::new();
        let token_manager = OAuth2TokenManager::new(service_account, http_client.clone());
        Ok(Self {
            project_id,
            http_client,
            token_manager,
            fcm_base_url: "https://fcm.googleapis.com".to_owned(),
        })
    }

    #[cfg(test)]
    pub fn with_urls(mut self, fcm_base_url: String, token_endpoint: String) -> Self {
        self.fcm_base_url = fcm_base_url;
        self.token_manager = self.token_manager.with_endpoint(token_endpoint);
        self
    }

    fn send_url(&self) -> String {
        format!(
            "{}/v1/projects/{}/messages:send",
            self.fcm_base_url, self.project_id
        )
    }

    async fn send_request(&self, body: &serde_json::Value) -> anyhow::Result<reqwest::Response> {
        let access_token = self.token_manager.get_access_token().await?;
        self.http_client
            .post(self.send_url())
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await
            .context("failed to send FCM request")
    }
}

#[async_trait]
impl FcmSender for FcmClient {
    async fn send_data_message(
        &self,
        device_token: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let data_map = convert_to_string_map(data)?;
        let body = serde_json::json!({
            "message": {
                "token": device_token,
                "data": data_map,
            }
        });

        let resp = self.send_request(&body).await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let error_body = resp.text().await.unwrap_or_default();
        let code = extract_fcm_error_code(&error_body);
        warn!(
            %status, fcm_error_code = %code,
            "FCM send_data_message failed: {error_body}"
        );
        Err(anyhow!("FCM send failed (HTTP {status}): {code}"))
    }
}

#[async_trait]
impl FcmValidator for FcmClient {
    async fn validate_token(&self, token: &str) -> anyhow::Result<bool> {
        let body = serde_json::json!({
            "validate_only": true,
            "message": {
                "token": token,
            }
        });

        let resp = self.send_request(&body).await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(true);
        }

        let error_body = resp.text().await.unwrap_or_default();
        let code = extract_fcm_error_code(&error_body);
        if code == "UNREGISTERED" || code == "INVALID_ARGUMENT" {
            return Ok(false);
        }

        warn!(
            %status, fcm_error_code = %code,
            "FCM validate_token failed: {error_body}"
        );
        Err(anyhow!("FCM validate failed (HTTP {status}): {code}"))
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
