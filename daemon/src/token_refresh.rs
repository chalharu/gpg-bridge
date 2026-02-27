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
mod tests {
    use super::*;

    #[test]
    fn decode_jws_payload_parses_valid_jwt() {
        let jwt = build_test_jwt(1000, 2000);
        let payload = decode_jws_payload(&jwt).unwrap();
        assert_eq!(payload.iat, Some(1000));
        assert_eq!(payload.exp, Some(2000));
    }

    #[test]
    fn decode_jws_payload_rejects_invalid_segment_count() {
        let result = decode_jws_payload("only.two");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("3 segments"));
    }

    #[test]
    fn decode_jws_payload_rejects_invalid_base64() {
        let result = decode_jws_payload("a.!!!.c");
        assert!(result.is_err());
    }

    #[test]
    fn needs_refresh_returns_true_when_near_expiry() {
        // Total lifetime = 900s, if remaining < 300s then needs refresh.
        // Set iat = now - 700, exp = now + 200 => remaining = 200 < 300
        let now = current_unix_timestamp();
        let jwt = build_test_jwt(now - 700, now + 200);
        assert!(needs_refresh(&jwt));
    }

    #[test]
    fn needs_refresh_returns_false_when_well_within_validity() {
        // Total lifetime = 900s, remaining = 800 => 800 >= 300
        let now = current_unix_timestamp();
        let jwt = build_test_jwt(now - 100, now + 800);
        assert!(!needs_refresh(&jwt));
    }

    #[test]
    fn needs_refresh_returns_true_when_expired() {
        let now = current_unix_timestamp();
        let jwt = build_test_jwt(now - 1000, now - 1);
        assert!(needs_refresh(&jwt));
    }

    #[test]
    fn needs_refresh_returns_false_without_exp() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{\"iat\":1000}");
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        assert!(!needs_refresh(&jwt));
    }

    #[test]
    fn needs_refresh_returns_false_without_iat() {
        let now = current_unix_timestamp();
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload_json = format!("{{\"exp\":{}}}", now + 1000);
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        assert!(!needs_refresh(&jwt));
    }

    #[test]
    fn needs_refresh_returns_false_for_invalid_jwt() {
        assert!(!needs_refresh("not-a-jwt"));
    }

    #[test]
    fn needs_refresh_returns_false_when_exp_lte_iat() {
        let jwt = build_test_jwt(2000, 1000);
        assert!(!needs_refresh(&jwt));
    }

    #[tokio::test]
    async fn refresh_token_handles_connection_error() {
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let result = refresh_token(&client, "http://127.0.0.1:1", "jwt").await;
        assert!(matches!(result, Err(TokenRefreshError::Other(_))));
    }

    #[tokio::test]
    async fn refresh_token_returns_re_pairing_on_401() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 401 Unauthorized\r\n\
                            Content-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let result = refresh_token(&client, &format!("http://{addr}"), "old-jwt").await;
        assert!(matches!(
            result,
            Err(TokenRefreshError::RePairingRequired { .. })
        ));
    }

    #[tokio::test]
    async fn refresh_token_returns_re_pairing_on_404() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 404 Not Found\r\n\
                            Content-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let result = refresh_token(&client, &format!("http://{addr}"), "old-jwt").await;
        assert!(matches!(
            result,
            Err(TokenRefreshError::RePairingRequired { .. })
        ));
    }

    #[tokio::test]
    async fn refresh_token_parses_new_jwt() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"client_jwt":"new-jwt-value"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let new_jwt = refresh_token(&client, &format!("http://{addr}"), "old-jwt")
            .await
            .unwrap();
        assert_eq!(new_jwt, "new-jwt-value");
    }

    #[tokio::test]
    async fn check_and_refresh_all_skips_when_no_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let client = Client::new();
        let summary = check_and_refresh_all(&client, "http://unused", &path)
            .await
            .unwrap();
        assert!(summary.re_pairing_needed.is_empty());
    }

    #[tokio::test]
    async fn check_and_refresh_all_refreshes_expired_token() {
        use crate::token_store::{TokenEntry, save_tokens};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        // Create a token that is nearly expired
        let now = current_unix_timestamp();
        let old_jwt = build_test_jwt(now - 900, now + 50);

        save_tokens(
            &path,
            &[TokenEntry {
                client_jwt: old_jwt,
                client_id: "cid-1".into(),
            }],
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"client_jwt":"refreshed-jwt"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let summary = check_and_refresh_all(&client, &format!("http://{addr}"), &path)
            .await
            .unwrap();

        assert!(summary.re_pairing_needed.is_empty());
        let entries = load_tokens(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].client_jwt, "refreshed-jwt");
    }

    #[tokio::test]
    async fn check_and_refresh_all_reports_re_pairing_needed() {
        use crate::token_store::{TokenEntry, save_tokens};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let now = current_unix_timestamp();
        let old_jwt = build_test_jwt(now - 900, now + 50);

        save_tokens(
            &path,
            &[TokenEntry {
                client_jwt: old_jwt,
                client_id: "cid-repa".into(),
            }],
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 401 Unauthorized\r\n\
                            Content-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let summary = check_and_refresh_all(&client, &format!("http://{addr}"), &path)
            .await
            .unwrap();

        assert_eq!(summary.re_pairing_needed, vec!["cid-repa"]);
    }
}
