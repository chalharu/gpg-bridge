use qrcode::QrCode;
use reqwest::Client;
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

use crate::http::build_bearer_header;
use crate::token_store::{TokenEntry, upsert_token};

const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 30_000;

#[derive(Debug, Deserialize)]
pub(crate) struct PairingTokenResponse {
    pub(crate) pairing_token: String,
    pub(crate) expires_in: u64,
}

#[derive(Debug)]
enum PairingSseError {
    Permanent(anyhow::Error),
    Transient(anyhow::Error),
}

pub(crate) async fn fetch_pairing_token(
    client: &Client,
    server_url: &str,
) -> anyhow::Result<PairingTokenResponse> {
    let url = format!("{}/pairing-token", server_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to request pairing token from {url}: {e}"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "pairing token request failed with status {} for {url}",
        response.status()
    );
    response
        .json::<PairingTokenResponse>()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse pairing token response: {e}"))
}

pub(crate) fn display_qr(
    writer: &mut dyn Write,
    pairing_token: &str,
    expires_in: u64,
) -> anyhow::Result<()> {
    let code = QrCode::new(pairing_token.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to create QR code: {e}"))?;
    let qr = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();
    writeln!(writer, "\n=== Pairing QR Code ===\n{qr}")?;
    writeln!(writer, "Scan this QR code with the gpg-bridge mobile app.")?;
    writeln!(writer, "The code expires in {expires_in} seconds.\n")?;
    Ok(())
}

fn classify_sse_status(status: reqwest::StatusCode, url: &str) -> PairingSseError {
    let err = anyhow::anyhow!("pairing SSE returned status {status} for {url}");
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::GONE => {
            PairingSseError::Permanent(err)
        }
        _ => PairingSseError::Transient(err),
    }
}

async fn try_pairing_sse(
    client: &Client,
    server_url: &str,
    pairing_jwt: &str,
) -> Result<TokenEntry, PairingSseError> {
    let url = format!("{}/pairing-session", server_url.trim_end_matches('/'));
    let bearer = build_bearer_header(pairing_jwt).map_err(PairingSseError::Permanent)?;

    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .header(reqwest::header::AUTHORIZATION, bearer)
        .send()
        .await
        .map_err(|e| PairingSseError::Transient(e.into()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(classify_sse_status(status, &url));
    }

    read_paired_from_stream(response).await
}

async fn read_paired_from_stream(
    response: reqwest::Response,
) -> Result<TokenEntry, PairingSseError> {
    use eventsource_stream::Eventsource;
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream().eventsource();

    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(event) if event.event == "paired" => {
                return parse_paired_event(&event.data).map_err(PairingSseError::Permanent);
            }
            Ok(_) => { /* ignore non-paired events (e.g. heartbeat) */ }
            Err(e) => {
                return Err(PairingSseError::Transient(anyhow::anyhow!(
                    "SSE stream error: {e}"
                )));
            }
        }
    }

    Err(PairingSseError::Transient(anyhow::anyhow!(
        "pairing SSE stream ended without paired event"
    )))
}

fn parse_paired_event(data: &str) -> anyhow::Result<TokenEntry> {
    serde_json::from_str(data).map_err(|e| anyhow::anyhow!("failed to parse paired event: {e}"))
}

fn pairing_backoff(attempt: u32) -> Duration {
    let base_ms = INITIAL_BACKOFF_MS
        .saturating_mul(2u64.saturating_pow(attempt.min(16)))
        .min(MAX_BACKOFF_MS);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let jitter_ms = seed % ((base_ms / 4).max(1) + 1);
    Duration::from_millis(base_ms.saturating_add(jitter_ms).min(MAX_BACKOFF_MS))
}

/// Wait for a `paired` SSE event, reconnecting on transient errors.
pub(crate) async fn wait_for_paired_event(
    client: &Client,
    server_url: &str,
    pairing_jwt: &str,
) -> anyhow::Result<TokenEntry> {
    let mut attempt: u32 = 0;
    loop {
        match try_pairing_sse(client, server_url, pairing_jwt).await {
            Ok(entry) => return Ok(entry),
            Err(PairingSseError::Permanent(e)) => return Err(e),
            Err(PairingSseError::Transient(e)) => {
                let delay = pairing_backoff(attempt);
                warn!(attempt, ?delay, error = %e, "pairing SSE failed; retrying");
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

pub(crate) fn display_pairing_complete(writer: &mut dyn Write) -> anyhow::Result<()> {
    write!(
        writer,
        "\n=== Pairing Complete ===\n\
         Your device has been successfully paired.\n\
         WARNING: If you did not initiate this pairing, remove it immediately.\n\
         Use the unpair command to remove unauthorized pairings.\n\n"
    )?;
    Ok(())
}

pub(crate) async fn run_pairing_flow(
    client: &Client,
    server_url: &str,
    token_store_path: &Path,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    info!("starting pairing flow");

    let pairing_response = fetch_pairing_token(client, server_url).await?;
    info!(
        expires_in = pairing_response.expires_in,
        "received pairing token"
    );

    display_qr(
        writer,
        &pairing_response.pairing_token,
        pairing_response.expires_in,
    )?;

    info!("waiting for mobile device to complete pairing...");
    let entry = wait_for_paired_event(client, server_url, &pairing_response.pairing_token).await?;

    info!(client_id = %entry.client_id, "pairing confirmed");
    upsert_token(token_store_path, entry)?;

    display_pairing_complete(writer)?;
    info!("pairing flow completed successfully");
    Ok(())
}

#[cfg(test)]
#[path = "test_http_server.rs"]
mod test_http_server;

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;
