use std::fmt;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use josekit::{
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_EXPIRY_BUFFER_SECS: i64 = 60;

/// Google service account key file structure.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: Option<String>,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"[REDACTED]")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// Cached OAuth2 access token with expiry.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Manages OAuth2 access tokens for Google APIs.
#[derive(Debug)]
pub struct OAuth2TokenManager {
    service_account: ServiceAccountKey,
    http_client: reqwest::Client,
    cache: Arc<RwLock<Option<CachedToken>>>,
    refresh_mutex: Arc<Mutex<()>>,
    token_endpoint: String,
}

impl OAuth2TokenManager {
    pub fn new(service_account: ServiceAccountKey, http_client: reqwest::Client) -> Self {
        let endpoint = service_account
            .token_uri
            .clone()
            .unwrap_or_else(|| TOKEN_ENDPOINT.to_owned());
        Self {
            service_account,
            http_client,
            cache: Arc::new(RwLock::new(None)),
            refresh_mutex: Arc::new(Mutex::new(())),
            token_endpoint: endpoint,
        }
    }

    #[cfg(test)]
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.token_endpoint = endpoint;
        self
    }

    /// Returns a valid access token, refreshing if needed.
    ///
    /// Uses a mutex with double-check locking to prevent thundering herd
    /// when multiple concurrent requests find the token expired.
    pub async fn get_access_token(&self) -> anyhow::Result<String> {
        if let Some(token) = self.read_cached_token().await {
            return Ok(token);
        }
        let _guard = self.refresh_mutex.lock().await;
        // Double-check: another task may have refreshed while we waited.
        if let Some(token) = self.read_cached_token().await {
            return Ok(token);
        }
        self.refresh_token().await
    }

    async fn read_cached_token(&self) -> Option<String> {
        let guard = self.cache.read().await;
        let cached = guard.as_ref()?;
        let now = chrono::Utc::now();
        if cached.expires_at > now {
            Some(cached.access_token.clone())
        } else {
            None
        }
    }

    async fn refresh_token(&self) -> anyhow::Result<String> {
        let assertion = self.create_signed_jwt()?;
        let response = self.exchange_token(&assertion).await?;
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(i64::from(response.expires_in) - TOKEN_EXPIRY_BUFFER_SECS);
        let token = response.access_token.clone();
        let mut guard = self.cache.write().await;
        *guard = Some(CachedToken {
            access_token: response.access_token,
            expires_at,
        });
        Ok(token)
    }

    fn create_signed_jwt(&self) -> anyhow::Result<String> {
        let now = chrono::Utc::now();
        let mut payload = JwtPayload::new();
        payload.set_issuer(&self.service_account.client_email);
        payload.set_claim(
            "scope",
            Some(serde_json::Value::String(FCM_SCOPE.to_owned())),
        )?;
        payload.set_claim(
            "aud",
            Some(serde_json::Value::String(self.token_endpoint.clone())),
        )?;
        payload.set_issued_at(&now.into());
        payload.set_expires_at(&(now + chrono::Duration::hours(1)).into());

        let mut header = JwsHeader::new();
        header.set_algorithm("RS256");
        header.set_token_type("JWT");

        let signer = RS256
            .signer_from_pem(&self.service_account.private_key)
            .context("failed to create RS256 signer from service account key")?;

        jwt::encode_with_signer(&payload, &header, &*signer)
            .context("failed to sign OAuth2 JWT assertion")
    }

    async fn exchange_token(&self, assertion: &str) -> anyhow::Result<TokenResponse> {
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let resp = self
            .http_client
            .post(&self.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("failed to send OAuth2 token request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "OAuth2 token exchange failed (HTTP {status}): {body}"
            ));
        }

        resp.json::<TokenResponse>()
            .await
            .context("failed to parse OAuth2 token response")
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
}

#[cfg(test)]
#[path = "oauth2_tests.rs"]
mod tests;
