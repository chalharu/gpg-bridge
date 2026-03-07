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

enum WaitDecision {
    Return(SignResult),
    Retry { delay: Duration, next_attempt: u32 },
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
        match evaluate_wait_decision(
            client, config, flow_state, &sse_url, &bearer, attempt, expiry,
        )
        .await?
        {
            WaitDecision::Return(result) => return Ok(result),
            WaitDecision::Retry {
                delay,
                next_attempt,
            } => {
                if sleep_until_or_expiry(delay, expiry).await {
                    return Ok(SignResult::Expired);
                }
                attempt = next_attempt;
            }
        }
    }
}

async fn evaluate_wait_decision(
    client: &Client,
    config: &SignEventSseConfig,
    flow_state: &SignFlowState,
    sse_url: &str,
    bearer: &HeaderValue,
    attempt: u32,
    expiry: tokio::time::Instant,
) -> anyhow::Result<WaitDecision> {
    match connect_sse(client, sse_url, bearer).await {
        ConnectOutcome::Response(response) => {
            handle_stream_response(response, config, flow_state, attempt, expiry).await
        }
        ConnectOutcome::RateLimit(retry_after) => {
            Ok(rate_limit_retry(config, attempt, retry_after))
        }
        ConnectOutcome::Error(err) => Ok(connect_error_retry(config, attempt, err)),
    }
}

async fn handle_stream_response(
    response: reqwest::Response,
    config: &SignEventSseConfig,
    flow_state: &SignFlowState,
    attempt: u32,
    expiry: tokio::time::Instant,
) -> anyhow::Result<WaitDecision> {
    match process_stream(response, config, flow_state, expiry).await {
        Ok(result) => Ok(WaitDecision::Return(result)),
        Err(StreamError::Terminal(err)) => Err(err),
        Err(StreamError::Transient(err)) => {
            tracing::debug!(?err, "SSE stream interrupted, reconnecting");
            Ok(WaitDecision::Retry {
                delay: compute_backoff(config, attempt),
                next_attempt: attempt.saturating_add(1),
            })
        }
    }
}

fn rate_limit_retry(
    config: &SignEventSseConfig,
    attempt: u32,
    retry_after: Duration,
) -> WaitDecision {
    let backoff = compute_backoff(config, attempt);
    WaitDecision::Retry {
        delay: std::cmp::max(backoff, retry_after),
        next_attempt: attempt.saturating_add(1),
    }
}

fn connect_error_retry(
    config: &SignEventSseConfig,
    attempt: u32,
    err: anyhow::Error,
) -> WaitDecision {
    tracing::warn!(?err, attempt, "sign-events SSE connect failed");
    WaitDecision::Retry {
        delay: compute_backoff(config, attempt),
        next_attempt: attempt.saturating_add(1),
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
#[path = "sign_event_sse_tests.rs"]
mod tests;
