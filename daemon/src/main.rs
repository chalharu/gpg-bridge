use clap::Parser;
use reqwest::{
    Client, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT},
};
use serde::Deserialize;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod sse;

use sse::{DaemonSseEvent, SseClient, SseClientConfig};

const DEFAULT_HTTP_TIMEOUT_SECONDS: u64 = 10;
const MAX_HTTP_RETRIES: u32 = 3;

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-daemon")]
struct Cli {
    #[arg(long)]
    server_url: Option<String>,
    #[arg(long)]
    socket_path: Option<String>,
    #[arg(long)]
    config_path: Option<PathBuf>,
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    server_url: Option<String>,
    socket_path: Option<String>,
    log_level: Option<String>,
}

#[derive(Debug, Clone)]
struct AppConfig {
    server_url: String,
    socket_path: String,
    log_level: String,
}

fn parse_cli_from<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::parse_from(args)
}

fn resolve_config_path(cli: &Cli, lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(path) = &cli.config_path {
        return Some(path.clone());
    }

    lookup("DAEMON_CONFIG_PATH").map(PathBuf::from)
}

fn parse_file_config(path: &Path, content: &str) -> anyhow::Result<FileConfig> {
    let extension = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "toml" => Ok(toml::from_str(content)?),
        "yaml" | "yml" => Ok(serde_yaml::from_str(content)?),
        _ => Err(anyhow::anyhow!(
            "unsupported config format: {} (expected .toml, .yaml, .yml)",
            path.display()
        )),
    }
}

fn load_file_config(path: Option<&Path>) -> anyhow::Result<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };

    let content = fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!("failed to read config file {}: {error}", path.display())
    })?;

    parse_file_config(path, &content)
}

fn require_http_url(server_url: &str) -> anyhow::Result<()> {
    if server_url.starts_with("http://") || server_url.starts_with("https://") {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "server_url must start with http:// or https://, got '{server_url}'"
    ))
}

fn build_app_config(
    cli: &Cli,
    file: &FileConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<AppConfig> {
    let server_url = cli
        .server_url
        .clone()
        .or_else(|| lookup("DAEMON_SERVER_URL"))
        .or_else(|| file.server_url.clone())
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_owned());

    require_http_url(&server_url)?;

    let socket_path = cli
        .socket_path
        .clone()
        .or_else(|| lookup("DAEMON_SOCKET_PATH"))
        .or_else(|| file.socket_path.clone())
        .unwrap_or_else(|| "tmp/S.gpg-agent".to_owned());

    if socket_path.trim().is_empty() {
        return Err(anyhow::anyhow!("socket_path must not be empty"));
    }

    let log_level = cli
        .log_level
        .clone()
        .or_else(|| lookup("DAEMON_LOG_LEVEL"))
        .or_else(|| file.log_level.clone())
        .unwrap_or_else(|| "info".to_owned());

    Ok(AppConfig {
        server_url,
        socket_path,
        log_level,
    })
}

fn build_env_filter(log_level: &str) -> anyhow::Result<EnvFilter> {
    Ok(EnvFilter::try_new(log_level)?)
}

fn setup_tracing(log_level: &str) -> anyhow::Result<()> {
    let env_filter = build_env_filter(log_level)?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
}

fn default_user_agent() -> String {
    format!("gpg-bridge-daemon/{}", env!("CARGO_PKG_VERSION"))
}

pub fn build_http_client(timeout: Duration, user_agent: &str) -> anyhow::Result<Client> {
    let client = Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .build()?;

    Ok(client)
}

pub fn build_bearer_header(token: &str) -> anyhow::Result<HeaderValue> {
    if token.trim().is_empty() {
        return Err(anyhow::anyhow!("bearer token must not be empty"));
    }

    Ok(HeaderValue::from_str(&format!("Bearer {token}"))?)
}

pub fn retry_delay_for(status: StatusCode, headers: &HeaderMap, attempt: u32) -> Option<Duration> {
    if attempt >= MAX_HTTP_RETRIES {
        return None;
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return headers
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .or_else(|| Some(Duration::from_secs(u64::from(attempt + 1))));
    }

    if status.is_server_error() {
        return Some(Duration::from_secs(2_u64.pow(attempt)));
    }

    None
}

pub fn map_status_error(status: StatusCode, url: &str) -> anyhow::Error {
    match status {
        StatusCode::UNAUTHORIZED => anyhow::anyhow!("authentication failed for {url} (401)"),
        StatusCode::FORBIDDEN => anyhow::anyhow!("permission denied for {url} (403)"),
        StatusCode::NOT_FOUND => anyhow::anyhow!("resource not found at {url} (404)"),
        StatusCode::TOO_MANY_REQUESTS => anyhow::anyhow!("rate limited by {url} (429)"),
        _ if status.is_server_error() => {
            anyhow::anyhow!("server error from {url} ({status})")
        }
        _ => anyhow::anyhow!("request failed for {url} ({status})"),
    }
}

pub async fn send_get_with_retry(
    client: &Client,
    url: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<String> {
    let mut attempt = 0;

    loop {
        let mut request = client.get(url).header(USER_AGENT, default_user_agent());

        if let Some(token) = bearer_token {
            request = request.header(AUTHORIZATION, build_bearer_header(token)?);
        }

        let response = request
            .send()
            .await
            .map_err(|error| anyhow::anyhow!("failed to send request to {url}: {error}"))?;

        let status = response.status();

        if status.is_success() {
            return response.text().await.map_err(|error| {
                anyhow::anyhow!("failed to read response body from {url}: {error}")
            });
        }

        if let Some(delay) = retry_delay_for(status, response.headers(), attempt) {
            attempt += 1;
            tokio::time::sleep(delay).await;
            continue;
        }

        return Err(map_status_error(status, url));
    }
}

async fn wait_for_shutdown_signal<F>(shutdown_signal: F) -> anyhow::Result<()>
where
    F: Future<Output = std::io::Result<()>>,
{
    shutdown_signal.await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli_from(std::env::args_os());
    let lookup = |key: &str| std::env::var(key).ok();
    let config_path = resolve_config_path(&cli, &lookup);
    let file_config = load_file_config(config_path.as_deref())?;
    let config = build_app_config(&cli, &file_config, &lookup)?;
    let http_client = build_http_client(
        Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECONDS),
        &default_user_agent(),
    )?;

    setup_tracing(&config.log_level)?;

    if let Some(token) = lookup("DAEMON_ACCESS_TOKEN") {
        let _ = build_bearer_header(&token)?;
    }

    info!(
        log_level = %config.log_level,
        server_url = %config.server_url,
        socket_path = %config.socket_path,
        http_timeout_seconds = DEFAULT_HTTP_TIMEOUT_SECONDS,
        max_http_retries = MAX_HTTP_RETRIES,
        "daemon started"
    );

    let sse_task = if let Some(sse_url) = lookup("DAEMON_SSE_URL") {
        let sse_client = SseClient::new(http_client.clone(), SseClientConfig::new(sse_url))?;

        Some(tokio::spawn(async move {
            let run_result = sse_client
                .run_with_handler(|event| async move {
                    match event {
                        DaemonSseEvent::Heartbeat => {
                            info!("sse heartbeat");
                        }
                        DaemonSseEvent::Message {
                            event_type,
                            id,
                            data,
                        } => {
                            info!(event_type = %event_type, event_id = ?id, data = %data, "sse event received");
                        }
                    }

                    Ok(())
                })
                .await;

            if let Err(error) = run_result {
                tracing::warn!(?error, "sse client stopped");
            }
        }))
    } else {
        None
    };

    info!("waiting for shutdown signal");

    wait_for_shutdown_signal(tokio::signal::ctrl_c()).await?;

    if let Some(task) = sse_task {
        task.abort();
        let _ = task.await;
    }

    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn cli_defaults_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-daemon"]);

        assert!(cli.log_level.is_none());
        assert!(cli.server_url.is_none());
        assert!(cli.socket_path.is_none());
        assert!(cli.config_path.is_none());
    }

    #[test]
    fn cli_custom_log_level_is_applied() {
        let cli = parse_cli_from([
            "gpg-bridge-daemon",
            "--server-url",
            "https://example.com",
            "--socket-path",
            "tmp/socket",
            "--config-path",
            "tmp/config.toml",
            "--log-level",
            "debug",
        ]);

        assert_eq!(cli.log_level, Some("debug".to_owned()));
        assert_eq!(cli.server_url, Some("https://example.com".to_owned()));
        assert_eq!(cli.socket_path, Some("tmp/socket".to_owned()));
        assert_eq!(cli.config_path, Some(PathBuf::from("tmp/config.toml")));
    }

    #[test]
    fn build_env_filter_accepts_valid_log_level() {
        let result = build_env_filter("debug");

        assert!(result.is_ok());
    }

    #[test]
    fn build_env_filter_rejects_invalid_log_level() {
        let result = build_env_filter("debug[");

        assert!(result.is_err());
    }

    #[test]
    fn parse_toml_file_config() {
        let mut file = Builder::new().suffix(".toml").tempfile().unwrap();
        write!(
            file,
            "server_url = 'https://daemon.example'\nsocket_path = 'tmp/daemon.sock'\nlog_level = 'debug'\n"
        )
        .unwrap();

        let config = load_file_config(Some(file.path())).unwrap();

        assert_eq!(config.server_url, Some("https://daemon.example".to_owned()));
        assert_eq!(config.socket_path, Some("tmp/daemon.sock".to_owned()));
        assert_eq!(config.log_level, Some("debug".to_owned()));
    }

    #[test]
    fn parse_yaml_file_config() {
        let mut file = Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(
            file,
            "server_url: https://daemon.example\nsocket_path: tmp/daemon.sock\nlog_level: warn\n"
        )
        .unwrap();

        let config = load_file_config(Some(file.path())).unwrap();

        assert_eq!(config.server_url, Some("https://daemon.example".to_owned()));
        assert_eq!(config.socket_path, Some("tmp/daemon.sock".to_owned()));
        assert_eq!(config.log_level, Some("warn".to_owned()));
    }

    #[test]
    fn cli_overrides_env_and_file_config() {
        let cli = parse_cli_from([
            "gpg-bridge-daemon",
            "--server-url",
            "https://cli.example",
            "--socket-path",
            "tmp/cli.sock",
            "--log-level",
            "error",
        ]);

        let file = FileConfig {
            server_url: Some("https://file.example".to_owned()),
            socket_path: Some("tmp/file.sock".to_owned()),
            log_level: Some("warn".to_owned()),
        };

        let lookup = |key: &str| match key {
            "DAEMON_SERVER_URL" => Some("https://env.example".to_owned()),
            "DAEMON_SOCKET_PATH" => Some("tmp/env.sock".to_owned()),
            "DAEMON_LOG_LEVEL" => Some("debug".to_owned()),
            _ => None,
        };

        let config = build_app_config(&cli, &file, &lookup).unwrap();

        assert_eq!(config.server_url, "https://cli.example");
        assert_eq!(config.socket_path, "tmp/cli.sock");
        assert_eq!(config.log_level, "error");
    }

    #[test]
    fn env_overrides_file_config() {
        let cli = parse_cli_from(["gpg-bridge-daemon"]);
        let file = FileConfig {
            server_url: Some("https://file.example".to_owned()),
            socket_path: Some("tmp/file.sock".to_owned()),
            log_level: Some("warn".to_owned()),
        };

        let lookup = |key: &str| match key {
            "DAEMON_SERVER_URL" => Some("https://env.example".to_owned()),
            "DAEMON_SOCKET_PATH" => Some("tmp/env.sock".to_owned()),
            "DAEMON_LOG_LEVEL" => Some("debug".to_owned()),
            _ => None,
        };

        let config = build_app_config(&cli, &file, &lookup).unwrap();

        assert_eq!(config.server_url, "https://env.example");
        assert_eq!(config.socket_path, "tmp/env.sock");
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn build_app_config_rejects_invalid_server_url() {
        let cli = parse_cli_from(["gpg-bridge-daemon", "--server-url", "localhost:3000"]);
        let file = FileConfig::default();
        let lookup = |_key: &str| None;

        let result = build_app_config(&cli, &file, &lookup);
        assert!(result.is_err());
    }

    #[test]
    fn build_bearer_header_adds_scheme() {
        let value = build_bearer_header("token-123").unwrap();

        assert_eq!(value.to_str().unwrap(), "Bearer token-123");
    }

    #[test]
    fn retry_delay_for_uses_retry_after_on_429() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));

        let delay = retry_delay_for(StatusCode::TOO_MANY_REQUESTS, &headers, 0).unwrap();

        assert_eq!(delay, Duration::from_secs(7));
    }

    #[tokio::test]
    async fn send_get_with_retry_sends_bearer_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut buffer = [0_u8; 2048];
            let bytes_read = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();

            request
        });

        let client = build_http_client(Duration::from_secs(2), "daemon-test/1.0").unwrap();
        let response =
            send_get_with_retry(&client, &format!("http://{addr}"), Some("secret-token"))
                .await
                .unwrap();

        let request = server.await.unwrap();
        let request_lower = request.to_ascii_lowercase();

        assert_eq!(response, "ok");
        assert!(request_lower.contains("authorization: bearer secret-token"));
        assert!(request_lower.contains("user-agent: gpg-bridge-daemon/"));
    }

    #[tokio::test]
    async fn wait_for_shutdown_signal_succeeds_when_signal_succeeds() {
        let result = wait_for_shutdown_signal(async { Ok(()) }).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_shutdown_signal_returns_error_when_signal_fails() {
        let result = wait_for_shutdown_signal(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "signal error",
            ))
        })
        .await;

        assert!(result.is_err());
    }
}
