use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use tracing::{info, warn};

use crate::token_store::{load_tokens, update_jwt};

#[derive(Debug, thiserror::Error)]
pub(crate) enum TokenRefreshError {
    #[error("re-pairing required: {reason}")]
    RePairingRequired { reason: String },
    #[error("token refresh failed: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Deserialize)]
struct JwtPayload {
    exp: Option<u64>,
    iat: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    client_jwt: String,
}

/// Extract the payload from a JWS (JSON Web Signature) token.
/// The JWS has three base64url-encoded dot-separated segments: header.payload.signature.
fn decode_jws_payload(token: &str) -> anyhow::Result<JwtPayload> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "invalid JWS: expected 3 segments, got {}",
            parts.len()
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow::anyhow!("failed to base64url-decode JWS payload: {e}"))?;
    let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse JWS payload JSON: {e}"))?;
    Ok(payload)
}

/// Check if the remaining validity is less than 1/3 of total lifetime.
/// Returns `true` when expired or when remaining < total_lifetime / 3.
fn is_within_refresh_window(iat: u64, exp: u64, now: u64) -> bool {
    if exp <= iat {
        return false;
    }
    if now >= exp {
        return true;
    }
    let total_lifetime = exp - iat;
    let remaining = exp - now;
    // Integer division truncation is intentional and acceptable here;
    // practical JWT lifetimes (hours-days) make sub-second precision irrelevant.
    remaining < total_lifetime / 3
}

/// Determine if a client_jwt needs refreshing.
///
/// Returns `true` if the remaining validity is less than 1/3 of the total lifetime.
/// If `exp` or `iat` is missing, returns `false`.
///
/// # Decode failures
///
/// Returns `false` for corrupt or invalid tokens. Such tokens cannot be
/// meaningfully refreshed; the user must resolve them through re-pairing.
pub(crate) fn needs_refresh(client_jwt: &str) -> bool {
    let payload = match decode_jws_payload(client_jwt) {
        Ok(p) => p,
        Err(e) => {
            warn!("could not decode JWT for refresh check: {e}");
            return false;
        }
    };

    match (payload.exp, payload.iat) {
        (Some(exp), Some(iat)) => is_within_refresh_window(iat, exp, current_unix_timestamp()),
        _ => false,
    }
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map an HTTP status to a `TokenRefreshError` if it indicates failure.
fn check_refresh_status(status: reqwest::StatusCode, url: &str) -> Result<(), TokenRefreshError> {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::NOT_FOUND {
        return Err(TokenRefreshError::RePairingRequired {
            reason: format!("server returned {status} for token refresh"),
        });
    }
    if !status.is_success() {
        return Err(TokenRefreshError::Other(anyhow::anyhow!(
            "token refresh failed with status {status} for {url}"
        )));
    }
    Ok(())
}

/// Refresh a client_jwt by calling `POST <server_url>/pairing/refresh`.
///
/// Returns `TokenRefreshError::RePairingRequired` on 401 or 404 responses.
pub(crate) async fn refresh_token(
    client: &Client,
    server_url: &str,
    client_jwt: &str,
) -> Result<String, TokenRefreshError> {
    let url = format!("{}/pairing/refresh", server_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .json(&serde_json::json!({ "client_jwt": client_jwt }))
        .send()
        .await
        .map_err(|e| {
            TokenRefreshError::Other(anyhow::anyhow!(
                "failed to send refresh request to {url}: {e}"
            ))
        })?;

    check_refresh_status(response.status(), &url)?;

    let body: RefreshResponse = response.json().await.map_err(|e| {
        TokenRefreshError::Other(anyhow::anyhow!("failed to parse refresh response: {e}"))
    })?;

    Ok(body.client_jwt)
}

/// Result of checking and refreshing all stored tokens.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RefreshSummary {
    /// Client IDs that require re-pairing (server returned 401/404).
    pub(crate) re_pairing_needed: Vec<String>,
}

/// Handle the result of a single token refresh attempt.
fn log_refresh_result(client_id: &str, result: &Result<String, TokenRefreshError>) {
    match result {
        Ok(_) => info!(client_id, "token refreshed successfully"),
        Err(TokenRefreshError::RePairingRequired { reason }) => {
            warn!(client_id, reason = %reason, "re-pairing required for this client");
        }
        Err(TokenRefreshError::Other(e)) => {
            warn!(client_id, error = %e, "failed to refresh token");
        }
    }
}

/// Check all stored tokens and refresh those that need it.
///
/// Returns a [`RefreshSummary`] containing client IDs that need re-pairing,
/// allowing the caller to notify the user.
pub(crate) async fn check_and_refresh_all(
    client: &Client,
    server_url: &str,
    store_path: &Path,
) -> anyhow::Result<RefreshSummary> {
    let entries = load_tokens(store_path)?;
    if entries.is_empty() {
        info!("no stored tokens to refresh");
        return Ok(RefreshSummary::default());
    }

    let mut summary = RefreshSummary::default();
    for entry in &entries {
        if !needs_refresh(&entry.client_jwt) {
            continue;
        }

        info!(client_id = %entry.client_id, "token needs refresh");
        let result = refresh_token(client, server_url, &entry.client_jwt).await;

        if let Ok(ref new_jwt) = result {
            update_jwt(store_path, &entry.client_id, new_jwt)?;
        }
        if matches!(&result, Err(TokenRefreshError::RePairingRequired { .. })) {
            summary.re_pairing_needed.push(entry.client_id.clone());
        }

        log_refresh_result(&entry.client_id, &result);
    }

    Ok(summary)
}

/// Build a minimal JWS token string for testing purposes.
#[cfg(test)]
fn build_test_jwt(iat: u64, exp: u64) -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload_json = format!("{{\"iat\":{iat},\"exp\":{exp}}}");
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(b"fakesig");
    format!("{header}.{payload}.{signature}")
}

#[cfg(test)]
#[path = "token_refresh_tests.rs"]
mod tests;
