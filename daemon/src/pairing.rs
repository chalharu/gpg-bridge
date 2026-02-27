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
mod tests {
    use super::*;

    #[test]
    fn display_qr_produces_qr_output() {
        let mut buf = Vec::new();
        display_qr(&mut buf, "test-token-123", 120).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Pairing QR Code"));
        // QR output should contain block characters or spaces
        assert!(output.contains(' '));
    }

    #[test]
    fn display_qr_handles_long_input() {
        let mut buf = Vec::new();
        display_qr(&mut buf, &"a".repeat(500), 60).unwrap();
    }

    #[tokio::test]
    async fn fetch_pairing_token_handles_connection_error() {
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let result = fetch_pairing_token(&client, "http://127.0.0.1:1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_pairing_token_parses_response() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let body = r#"{"pairing_token":"tok-abc","expires_in":300}"#;
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
        let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.pairing_token, "tok-abc");
        assert_eq!(resp.expires_in, 300);
    }

    #[tokio::test]
    async fn fetch_pairing_token_returns_error_on_non_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 500 Internal Server Error\r\n\
                            Content-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn wait_for_paired_event_extracts_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let sse_body = concat!(
                "event: heartbeat\ndata: \n\n",
                "event: paired\n",
                "data: {\"client_jwt\":\"jwt-xyz\",\"client_id\":\"cid-123\"}\n\n",
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\r\n\
                 {sse_body}"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
            .await
            .unwrap();
        assert_eq!(entry.client_jwt, "jwt-xyz");
        assert_eq!(entry.client_id, "cid-123");
    }

    #[tokio::test]
    async fn wait_for_paired_event_aborts_on_401() {
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
        let result = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn wait_for_paired_event_retries_on_503_then_succeeds() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            // First connection: transient 503
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 503 Service Unavailable\r\n\
                            Content-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
            drop(socket);

            // Second connection: success
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let sse_body = "event: paired\n\
                            data: {\"client_jwt\":\"jwt-r\",\"client_id\":\"cid-r\"}\n\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\r\n\
                 {sse_body}"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
            .await
            .unwrap();
        assert_eq!(entry.client_jwt, "jwt-r");
        assert_eq!(entry.client_id, "cid-r");
    }

    #[test]
    fn display_pairing_complete_writes_warning() {
        let mut buf = Vec::new();
        display_pairing_complete(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Pairing Complete"));
        assert!(output.contains("did not initiate this pairing"));
        assert!(output.contains("unpair"));
    }

    #[tokio::test]
    async fn run_pairing_flow_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            // First connection: pairing-token
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"pairing_token":"pt-1","expires_in":60}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            drop(socket);

            // Second connection: pairing-session SSE
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let sse_body =
                "event: paired\ndata: {\"client_jwt\":\"jwt-1\",\"client_id\":\"cid-1\"}\n\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\r\n\
                 {sse_body}"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("tokens.json");
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let mut output = Vec::new();
        run_pairing_flow(&client, &format!("http://{addr}"), &token_path, &mut output)
            .await
            .unwrap();

        let entries = crate::token_store::load_tokens(&token_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].client_id, "cid-1");
        assert_eq!(entries[0].client_jwt, "jwt-1");

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Pairing QR Code"));
        assert!(output_str.contains("Pairing Complete"));
    }
}
