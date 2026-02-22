use std::net::SocketAddr;

use anyhow::{Context, anyhow};
use axum::{Json, Router, routing::get};
use clap::Parser;
use serde::Serialize;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-server")]
struct Cli {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
}

fn parse_cli_from<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::parse_from(args)
}

#[derive(Debug, Clone)]
struct AppConfig {
    server_host: String,
    server_port: u16,
    database_url: String,
    log_level: String,
    log_format: String,
}

#[derive(Debug, Clone)]
struct AppState {
    config: AppConfig,
}

impl AppConfig {
    fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let server_host = lookup("SERVER_HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
        let server_port_raw = lookup("SERVER_PORT").unwrap_or_else(|| "3000".to_owned());
        let server_port: u16 = server_port_raw
            .parse()
            .with_context(|| format!("SERVER_PORT must be a valid u16, got '{server_port_raw}'"))?;

        let database_url = lookup("SERVER_DATABASE_URL")
            .ok_or_else(|| anyhow!("missing required environment variable: SERVER_DATABASE_URL"))?;

        let log_level = lookup("SERVER_LOG_LEVEL").unwrap_or_else(|| "info".to_owned());
        let log_format = lookup("SERVER_LOG_FORMAT").unwrap_or_else(|| "plain".to_owned());

        Ok(Self {
            server_host,
            server_port,
            database_url,
            log_level,
            log_format,
        })
    }
}

fn init_tracing(config: &AppConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(config.log_level.clone()))
        .context("failed to initialize tracing env filter")?;

    let format = config.log_format.to_ascii_lowercase();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE);

    match format.as_str() {
        "plain" => builder
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))?,
        "json" => builder
            .json()
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))?,
        _ => {
            return Err(anyhow!(
                "SERVER_LOG_FORMAT must be either 'plain' or 'json', got '{format}'"
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<HealthResponse> {
    let _ = (&state.config.database_url, &state.config.log_level);
    Json(HealthResponse { status: "ok" })
}

fn parse_socket_addr(host: &str, port: u16) -> Result<SocketAddr, std::net::AddrParseError> {
    format!("{}:{}", host, port).parse()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    let cli = parse_cli_from(std::env::args_os());
    let config = AppConfig::from_env()?;
    init_tracing(&config)?;

    let host = cli.host.unwrap_or_else(|| config.server_host.clone());
    let port = cli.port.unwrap_or(config.server_port);
    let addr = parse_socket_addr(&host, port)?;

    let request_id_header = axum::http::header::HeaderName::from_static("x-request-id");

    let state = AppState { config };
    let app = Router::new()
        .route("/", get(health))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!(%addr, "server listening");

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-server"]);

        assert_eq!(cli.host, None);
        assert_eq!(cli.port, None);
    }

    #[test]
    fn cli_custom_values_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-server", "--host", "0.0.0.0", "--port", "8080"]);

        assert_eq!(cli.host, Some("0.0.0.0".to_owned()));
        assert_eq!(cli.port, Some(8080));
    }

    #[test]
    fn parse_cli_from_accepts_short_args_array() {
        let cli = parse_cli_from(["gpg-bridge-server", "--port", "3001"]);

        assert_eq!(cli.host, None);
        assert_eq!(cli.port, Some(3001));
    }

    #[test]
    fn config_uses_defaults_and_required_values() {
        let config = AppConfig::from_lookup(&|key| {
            if key == "SERVER_DATABASE_URL" {
                return Some("postgres://localhost:5432/gpg_bridge".to_owned());
            }
            None
        })
        .unwrap();

        assert_eq!(config.server_host, "127.0.0.1");
        assert_eq!(config.server_port, 3000);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, "plain");
        assert_eq!(config.database_url, "postgres://localhost:5432/gpg_bridge");
    }

    #[test]
    fn config_returns_error_when_required_env_is_missing() {
        let result = AppConfig::from_lookup(&|_| None);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("SERVER_DATABASE_URL")
        );
    }

    #[test]
    fn parse_socket_addr_returns_error_for_invalid_host() {
        let result = parse_socket_addr("invalid host", 3000);

        assert!(result.is_err());
    }

    #[test]
    fn parse_socket_addr_returns_expected_value_for_valid_input() {
        let result = parse_socket_addr("127.0.0.1", 8080);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn health_returns_ok_status() {
        let state = AppState {
            config: AppConfig {
                server_host: "127.0.0.1".to_owned(),
                server_port: 3000,
                database_url: "postgres://localhost:5432/gpg_bridge".to_owned(),
                log_level: "info".to_owned(),
                log_format: "plain".to_owned(),
            },
        };

        let Json(response) = health(axum::extract::State(state)).await;

        assert_eq!(response.status, "ok");
    }

    #[test]
    fn init_tracing_rejects_invalid_log_format() {
        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "postgres://localhost:5432/gpg_bridge".to_owned(),
            log_level: "info".to_owned(),
            log_format: "invalid".to_owned(),
        };

        let result = init_tracing(&config);
        assert!(result.is_err());
    }
}
