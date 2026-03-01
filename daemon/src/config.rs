use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

fn fallback_socket_path(lookup: &dyn Fn(&str) -> Option<String>) -> String {
    if let Some(home) = lookup("HOME") {
        format!("{home}/.gnupg/S.gpg-agent")
    } else {
        "/tmp/gpg-bridge/S.gpg-agent".to_owned()
    }
}

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-daemon")]
pub(crate) struct Cli {
    #[arg(long)]
    server_url: Option<String>,
    #[arg(long)]
    socket_path: Option<String>,
    #[arg(long)]
    config_path: Option<PathBuf>,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long)]
    kill_existing_agent: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct FileConfig {
    server_url: Option<String>,
    socket_path: Option<String>,
    log_level: Option<String>,
    kill_existing_agent: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct AppConfig {
    pub(crate) server_url: String,
    pub(crate) socket_path: String,
    pub(crate) allow_replace_existing_socket: bool,
    pub(crate) log_level: String,
    pub(crate) kill_existing_agent: bool,
    #[cfg(unix)]
    pub(crate) compat_socket_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketPathSource {
    Cli,
    Env,
    File,
    Detected,
    Fallback,
}

fn resolve_socket_path(
    cli: &Cli,
    file: &FileConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
    detected_default_socket_path: Option<&str>,
) -> anyhow::Result<(String, SocketPathSource)> {
    let (socket_path, source) = if let Some(value) = cli.socket_path.clone() {
        (value, SocketPathSource::Cli)
    } else if let Some(value) = lookup("DAEMON_SOCKET_PATH") {
        (value, SocketPathSource::Env)
    } else if let Some(value) = file.socket_path.clone() {
        (value, SocketPathSource::File)
    } else if let Some(value) = detected_default_socket_path {
        (value.to_owned(), SocketPathSource::Detected)
    } else {
        (fallback_socket_path(lookup), SocketPathSource::Fallback)
    };

    if socket_path.trim().is_empty() {
        return Err(anyhow::anyhow!("socket_path must not be empty"));
    }

    Ok((socket_path, source))
}

#[cfg(unix)]
fn resolve_compat_socket_path(
    socket_path: &str,
    detected_default_socket_path: Option<&str>,
) -> Option<PathBuf> {
    let default_socket_path = Path::new(detected_default_socket_path?);
    let selected_socket_path = Path::new(socket_path);

    if default_socket_path == selected_socket_path {
        return None;
    }

    Some(default_socket_path.to_path_buf())
}

pub(crate) fn parse_cli_from<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::parse_from(args)
}

pub(crate) fn resolve_config_path(
    cli: &Cli,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
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
        "yaml" | "yml" => Ok(serde_yml::from_str(content)?),
        _ => Err(anyhow::anyhow!(
            "unsupported config format: {} (expected .toml, .yaml, .yml)",
            path.display()
        )),
    }
}

pub(crate) fn load_file_config(path: Option<&Path>) -> anyhow::Result<FileConfig> {
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

pub(crate) fn build_app_config(
    cli: &Cli,
    file: &FileConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
    detected_default_socket_path: Option<&str>,
) -> anyhow::Result<AppConfig> {
    let server_url = cli
        .server_url
        .clone()
        .or_else(|| lookup("DAEMON_SERVER_URL"))
        .or_else(|| file.server_url.clone())
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_owned());

    require_http_url(&server_url)?;

    let log_level = cli
        .log_level
        .clone()
        .or_else(|| lookup("DAEMON_LOG_LEVEL"))
        .or_else(|| file.log_level.clone())
        .unwrap_or_else(|| "info".to_owned());

    let kill_existing_agent = cli.kill_existing_agent
        || lookup("DAEMON_KILL_EXISTING_AGENT")
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .or(file.kill_existing_agent)
            .unwrap_or(false);

    let detected_default_socket_path = if kill_existing_agent {
        detected_default_socket_path
    } else {
        None
    };

    let (socket_path, socket_path_source) =
        resolve_socket_path(cli, file, lookup, detected_default_socket_path)?;

    let allow_replace_existing_socket =
        kill_existing_agent || !matches!(socket_path_source, SocketPathSource::Detected);

    #[cfg(unix)]
    let compat_socket_path = resolve_compat_socket_path(&socket_path, detected_default_socket_path);

    Ok(AppConfig {
        server_url,
        socket_path,
        allow_replace_existing_socket,
        log_level,
        kill_existing_agent,
        #[cfg(unix)]
        compat_socket_path,
    })
}

fn build_env_filter(log_level: &str) -> anyhow::Result<EnvFilter> {
    Ok(EnvFilter::try_new(log_level)?)
}

pub(crate) fn setup_tracing(log_level: &str) -> anyhow::Result<()> {
    let env_filter = build_env_filter(log_level)?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
