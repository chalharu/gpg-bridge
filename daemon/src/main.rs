use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    setup_tracing(&config.log_level)?;

    info!(
        log_level = %config.log_level,
        server_url = %config.server_url,
        socket_path = %config.socket_path,
        "daemon started"
    );
    info!("waiting for shutdown signal");

    wait_for_shutdown_signal(tokio::signal::ctrl_c()).await?;

    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let path = Path::new("tmp/test.toml");
        let config = parse_file_config(
            path,
            "server_url = 'https://daemon.example'\nsocket_path = 'tmp/daemon.sock'\nlog_level = 'debug'\n",
        )
        .unwrap();

        assert_eq!(config.server_url, Some("https://daemon.example".to_owned()));
        assert_eq!(config.socket_path, Some("tmp/daemon.sock".to_owned()));
        assert_eq!(config.log_level, Some("debug".to_owned()));
    }

    #[test]
    fn parse_yaml_file_config() {
        let path = Path::new("tmp/test.yaml");
        let config = parse_file_config(
            path,
            "server_url: https://daemon.example\nsocket_path: tmp/daemon.sock\nlog_level: warn\n",
        )
        .unwrap();

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
