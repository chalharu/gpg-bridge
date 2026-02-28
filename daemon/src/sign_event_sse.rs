//! SSE client for waiting on sign-request results.
//!
//! Connects to `GET /sign-events` with `daemon_auth_jws` Bearer tokens,
//! handles heartbeat/signature events, and decrypts E2E encrypted results.

use std::time::Duration;

use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

use crate::e2e_crypto;
use crate::http::build_bearer_header;
use crate::sign_flow::SignFlowState;

/// Outcome of waiting for a signature decision via SSE.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignResult {
    Approved { signature: Vec<u8> },
    Denied,
    Unavailable,
    Expired,
    Cancelled,
}

/// Configuration for the sign-events SSE client.
#[derive(Debug, Clone)]
pub(crate) struct SignEventSseConfig {
    pub(crate) heartbeat_timeout: Duration,
    pub(crate) initial_backoff: Duration,
    pub(crate) max_backoff: Duration,
}

impl Default for SignEventSseConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout: Duration::from_secs(60),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

#[derive(Deserialize)]
struct SignatureEventData {
    status: String,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct DecryptedPayload {
    signature: String,
}

enum ConnectOutcome {
    Response(reqwest::Response),
    RateLimit(Duration),
    Error(anyhow::Error),
}

/// Classification of errors during SSE stream processing.
#[derive(Debug)]
enum StreamError {
    /// Retriable errors (stream close, heartbeat timeout, etc.)
    Transient(anyhow::Error),
    /// Non-retriable errors (decryption failure, bad event data, etc.)
    Terminal(anyhow::Error),
}

/// Wait for a sign-request result via SSE with automatic reconnection.
///
/// Connects to `GET {server_url}/sign-events`, processes events,
/// and returns when a terminal signature event is received or the request JWT expires.
pub(crate) async fn wait_for_sign_result(
    client: &Client,
    config: &SignEventSseConfig,
    flow_state: &SignFlowState,
) -> anyhow::Result<SignResult> {
    let sse_url = format!("{}/sign-events", flow_state.server_url);
    let mut attempt: u32 = 0;
    let expiry = tokio::time::Instant::now() + remaining_until_expiry(flow_state);

    loop {
        if tokio::time::Instant::now() >= expiry {
            return Ok(SignResult::Expired);
        }

        let bearer = build_sse_bearer(flow_state, &sse_url)?;
        match connect_sse(client, &sse_url, &bearer).await {
            ConnectOutcome::Response(resp) => {
                attempt = 0;
                match process_stream(resp, config, flow_state, expiry).await {
                    Ok(result) => return Ok(result),
                    Err(StreamError::Terminal(err)) => {
                        return Err(err);
                    }
                    Err(StreamError::Transient(err)) => {
                        tracing::debug!(?err, "SSE stream interrupted, reconnecting");
                        let delay = compute_backoff(config, attempt);
                        if sleep_until_or_expiry(delay, expiry).await {
                            return Ok(SignResult::Expired);
                        }
                        attempt = attempt.saturating_add(1);
                    }
                }
            }
            ConnectOutcome::RateLimit(retry_after) => {
                let backoff = compute_backoff(config, attempt);
                let delay = std::cmp::max(backoff, retry_after);
                if sleep_until_or_expiry(delay, expiry).await {
                    return Ok(SignResult::Expired);
                }
                attempt = attempt.saturating_add(1);
            }
            ConnectOutcome::Error(err) => {
                tracing::warn!(?err, attempt, "sign-events SSE connect failed");
                let delay = compute_backoff(config, attempt);
                if sleep_until_or_expiry(delay, expiry).await {
                    return Ok(SignResult::Expired);
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

fn build_sse_bearer(flow_state: &SignFlowState, aud: &str) -> anyhow::Result<HeaderValue> {
    let jws = e2e_crypto::sign_daemon_auth_jws(
        &flow_state.auth_private_jwk,
        &flow_state.auth_kid,
        &flow_state.request_jwt,
        aud,
        flow_state.request_jwt_exp,
    )?;
    build_bearer_header(&jws)
}

async fn connect_sse(client: &Client, url: &str, bearer: &HeaderValue) -> ConnectOutcome {
    let result = client
        .get(url)
        .header(ACCEPT, HeaderValue::from_static("text/event-stream"))
        .header(AUTHORIZATION, bearer)
        .send()
        .await;

    match result {
        Err(e) => ConnectOutcome::Error(anyhow!("SSE connection failed: {e}")),
        Ok(resp) if resp.status().is_success() => ConnectOutcome::Response(resp),
        Ok(resp) if resp.status() == StatusCode::TOO_MANY_REQUESTS => {
            let retry_after = parse_retry_after_header(&resp);
            ConnectOutcome::RateLimit(retry_after.unwrap_or(Duration::from_secs(1)))
        }
        Ok(resp) => ConnectOutcome::Error(anyhow!("SSE endpoint returned {}", resp.status())),
    }
}

async fn process_stream(
    response: reqwest::Response,
    config: &SignEventSseConfig,
    flow_state: &SignFlowState,
    expiry: tokio::time::Instant,
) -> Result<SignResult, StreamError> {
    let mut stream = response.bytes_stream().eventsource();
    let expiry_sleep = tokio::time::sleep_until(expiry);
    tokio::pin!(expiry_sleep);

    loop {
        let next = tokio::select! {
            result = tokio::time::timeout(config.heartbeat_timeout, stream.next()) => result,
            () = &mut expiry_sleep => {
                return Ok(SignResult::Expired);
            }
        };

        match next {
            Ok(Some(Ok(event))) => {
                if event.event == "heartbeat" {
                    continue;
                }
                if event.event == "signature" {
                    return handle_signature_event(&event.data, flow_state)
                        .map_err(StreamError::Terminal);
                }
                tracing::debug!(event_type = %event.event, "ignoring unknown SSE event");
            }
            Ok(Some(Err(e))) => {
                return Err(StreamError::Transient(anyhow!("SSE stream error: {e}")));
            }
            Ok(None) => {
                return Err(StreamError::Transient(anyhow!(
                    "SSE stream ended unexpectedly"
                )));
            }
            Err(_) => {
                return Err(StreamError::Transient(anyhow!("heartbeat timeout")));
            }
        }
    }
}

fn handle_signature_event(data: &str, flow_state: &SignFlowState) -> anyhow::Result<SignResult> {
    let event: SignatureEventData =
        serde_json::from_str(data).map_err(|e| anyhow!("invalid signature event data: {e}"))?;

    match event.status.as_str() {
        "approved" => decrypt_approved_signature(&event, flow_state),
        "denied" => Ok(SignResult::Denied),
        "unavailable" => Ok(SignResult::Unavailable),
        "expired" => Ok(SignResult::Expired),
        "cancelled" => Ok(SignResult::Cancelled),
        other => Err(anyhow!("unknown signature status: {other}")),
    }
}

fn decrypt_approved_signature(
    event: &SignatureEventData,
    flow_state: &SignFlowState,
) -> anyhow::Result<SignResult> {
    let jwe = event
        .signature
        .as_deref()
        .ok_or_else(|| anyhow!("approved event missing signature field"))?;
    let plaintext = e2e_crypto::decrypt_jwe(jwe, &flow_state.enc_private_jwk)?;
    let payload: DecryptedPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| anyhow!("invalid decrypted payload: {e}"))?;
    let signature = BASE64
        .decode(&payload.signature)
        .map_err(|e| anyhow!("invalid base64 signature: {e}"))?;
    Ok(SignResult::Approved { signature })
}

fn remaining_until_expiry(flow_state: &SignFlowState) -> Duration {
    let now = chrono::Utc::now().timestamp();
    let remaining = flow_state.request_jwt_exp - now;
    if remaining <= 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(remaining as u64)
    }
}

/// Sleep for `delay`, returning early if expiry is reached. Returns `true` if expired.
async fn sleep_until_or_expiry(delay: Duration, expiry: tokio::time::Instant) -> bool {
    let wake_at = (tokio::time::Instant::now() + delay).min(expiry);
    tokio::time::sleep_until(wake_at).await;
    tokio::time::Instant::now() >= expiry
}

fn compute_backoff(config: &SignEventSseConfig, attempt: u32) -> Duration {
    let exponent = attempt.min(16);
    let base = config
        .initial_backoff
        .saturating_mul(2_u32.saturating_pow(exponent))
        .min(config.max_backoff);
    // Subtract up to 25% of base so jitter always works, even at max_backoff.
    let jitter_bound_millis = base.as_millis() as u64 / 4;
    if jitter_bound_millis == 0 {
        return base;
    }
    let jitter_millis = jitter_seed() % (jitter_bound_millis + 1);
    base.saturating_sub(Duration::from_millis(jitter_millis))
}

/// Returns a non-cryptographic seed for backoff jitter.
///
/// Uses `SystemTime` for simplicity. This is acceptable because jitter
/// is not security-sensitive — it only decorrelates retry timing.
fn jitter_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn parse_retry_after_header(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
// NOTE: This module is test-heavy (~430 lines of tests vs ~260 lines of implementation).
// This is intentional — SSE reconnection logic requires extensive integration tests.
mod tests {
    use super::*;
    use crate::e2e_crypto;
    use crate::http::build_http_client;
    use crate::sign_flow::SignFlowState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn dummy_flow_state() -> SignFlowState {
        let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
        let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
        SignFlowState {
            auth_private_jwk: auth_priv,
            auth_kid,
            enc_private_jwk: enc_priv,
            request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
            request_jwt_exp: 1_900_000_000,
            server_url: "http://localhost:0".to_owned(),
        }
    }

    fn flow_state_with_url(url: &str) -> (SignFlowState, serde_json::Value) {
        let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
        let (enc_priv, enc_pub) = e2e_crypto::generate_ecdh_keypair().unwrap();
        let state = SignFlowState {
            auth_private_jwk: auth_priv,
            auth_kid,
            enc_private_jwk: enc_priv,
            request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
            request_jwt_exp: 1_900_000_000,
            server_url: url.to_owned(),
        };
        (state, enc_pub)
    }

    fn fast_config() -> SignEventSseConfig {
        SignEventSseConfig {
            heartbeat_timeout: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(200),
        }
    }

    fn sse_headers() -> &'static str {
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: close\r\n\r\n",
        )
    }

    fn approved_jwe(enc_pub: &serde_json::Value, sig_bytes: &[u8]) -> String {
        let payload = serde_json::json!({ "signature": BASE64.encode(sig_bytes) });
        let plaintext = serde_json::to_vec(&payload).unwrap();
        e2e_crypto::encrypt_jwe_a256kw(enc_pub, &plaintext).unwrap()
    }

    #[tokio::test]
    async fn approved_returns_decrypted_signature() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, enc_pub) = flow_state_with_url(&format!("http://{addr}"));
        let jwe = approved_jwe(&enc_pub, &[0xDE, 0xAD, 0xBE, 0xEF]);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let event_data = serde_json::json!({"status": "approved", "signature": jwe});
            let body = format!(
                "{}event: signature\ndata: {}\n\n",
                sse_headers(),
                event_data,
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(
            result,
            SignResult::Approved {
                signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }
        );
    }

    #[tokio::test]
    async fn denied_status_returns_denied() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn unavailable_status_returns_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"unavailable\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Unavailable);
    }

    #[tokio::test]
    async fn expired_status_returns_expired() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"expired\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Expired);
    }

    #[tokio::test]
    async fn cancelled_status_returns_cancelled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"cancelled\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Cancelled);
    }

    #[tokio::test]
    async fn heartbeat_before_signature_is_handled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                concat!(
                    "{}",
                    "event: heartbeat\ndata: {{}}\n\n",
                    "event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                ),
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn expired_jwt_returns_expired_immediately() {
        let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
        let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
        let flow_state = SignFlowState {
            auth_private_jwk: auth_priv,
            auth_kid,
            enc_private_jwk: enc_priv,
            request_jwt: "fake.eyJleHAiOjB9.sig".to_owned(),
            request_jwt_exp: 0,
            server_url: "http://localhost:0".to_owned(),
        };

        let client = build_http_client(Duration::from_secs(1), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Expired);
    }

    #[tokio::test]
    async fn reconnects_on_server_error_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            // First connection: 500 error
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                )
                .await
                .unwrap();

            // Second connection: success with denied
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn reconnects_on_stream_close_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            // First connection: send headers then close
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Connection: close\r\n\r\n",
                )
                .await
                .unwrap();
            drop(socket);

            // Second connection: success
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn bearer_token_sent_in_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
            request
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();

        let request = server.await.unwrap();
        assert!(
            request.contains("GET /sign-events"),
            "must be GET /sign-events"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer"),
            "must have Bearer auth"
        );
    }

    #[test]
    fn handle_signature_event_unknown_status_errors() {
        let flow_state = dummy_flow_state();
        let data = r#"{"status":"unknown_status"}"#;
        assert!(handle_signature_event(data, &flow_state).is_err());
    }

    #[test]
    fn handle_signature_event_approved_missing_signature_field() {
        let flow_state = dummy_flow_state();
        let data = r#"{"status":"approved"}"#;
        assert!(handle_signature_event(data, &flow_state).is_err());
    }

    #[test]
    fn handle_signature_event_invalid_json_errors() {
        let flow_state = dummy_flow_state();
        assert!(handle_signature_event("not json", &flow_state).is_err());
    }

    #[test]
    fn handle_signature_event_denied() {
        let flow_state = dummy_flow_state();
        let result = handle_signature_event(r#"{"status":"denied"}"#, &flow_state).unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[test]
    fn handle_signature_event_unavailable() {
        let flow_state = dummy_flow_state();
        let result = handle_signature_event(r#"{"status":"unavailable"}"#, &flow_state).unwrap();
        assert_eq!(result, SignResult::Unavailable);
    }

    #[test]
    fn remaining_until_expiry_far_future() {
        let flow_state = dummy_flow_state();
        let remaining = remaining_until_expiry(&flow_state);
        assert!(remaining > Duration::ZERO);
    }

    #[test]
    fn remaining_until_expiry_past_returns_zero() {
        let mut flow_state = dummy_flow_state();
        flow_state.request_jwt_exp = 0;
        assert_eq!(remaining_until_expiry(&flow_state), Duration::ZERO);
    }

    #[test]
    fn compute_backoff_increases_with_attempts() {
        let config = SignEventSseConfig {
            heartbeat_timeout: Duration::from_secs(60),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        };
        let b0 = compute_backoff(&config, 0);
        let b3 = compute_backoff(&config, 3);
        assert!(b3 > b0, "backoff should increase with attempts");
    }

    #[test]
    fn compute_backoff_capped_at_max() {
        let config = SignEventSseConfig {
            heartbeat_timeout: Duration::from_secs(60),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        };
        let b = compute_backoff(&config, 20);
        assert!(b <= config.max_backoff);
    }

    #[test]
    fn default_config_values() {
        let config = SignEventSseConfig::default();
        assert_eq!(config.heartbeat_timeout, Duration::from_secs(60));
        assert_eq!(config.initial_backoff, Duration::from_secs(1));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn retry_after_429_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            // First connection: 429 with Retry-After
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\n\
                      Retry-After: 1\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\r\n",
                )
                .await
                .unwrap();

            // Second connection: success with denied
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(5), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn heartbeat_timeout_triggers_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        let config = SignEventSseConfig {
            heartbeat_timeout: Duration::from_millis(500),
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(200),
        };

        tokio::spawn(async move {
            // First connection: send headers but no events — heartbeat timeout fires
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(sse_headers().as_bytes()).await.unwrap();

            // Second connection: success with signature event
            let (mut socket2, _) = listener.accept().await.unwrap();
            let _ = socket2.read(&mut buf).await.unwrap();
            let body = format!(
                "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
                sse_headers(),
            );
            socket2.write_all(body.as_bytes()).await.unwrap();
            // Keep first socket alive until second is complete
            drop(socket);
        });

        let client = build_http_client(Duration::from_secs(5), "test").unwrap();
        let result = wait_for_sign_result(&client, &config, &flow_state)
            .await
            .unwrap();
        assert_eq!(result, SignResult::Denied);
    }

    #[tokio::test]
    async fn decryption_failure_returns_terminal_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            // Send approved event with invalid JWE — should cause terminal error
            let event_data = serde_json::json!({"status": "approved", "signature": "invalid-jwe"});
            let body = format!(
                "{}event: signature\ndata: {}\n\n",
                sse_headers(),
                event_data,
            );
            socket.write_all(body.as_bytes()).await.unwrap();
        });

        let client = build_http_client(Duration::from_secs(2), "test").unwrap();
        let result = wait_for_sign_result(&client, &fast_config(), &flow_state).await;
        assert!(
            result.is_err(),
            "decryption failure should be a terminal error, not a retry"
        );
    }
}
