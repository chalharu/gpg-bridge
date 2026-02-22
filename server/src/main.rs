use std::net::SocketAddr;

use clap::Parser;
use gpg_bridge_server::{
    config::AppConfig,
    http::{AppState, build_router},
    observability::init_tracing,
    repository::build_repository,
};
use tracing::info;

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

    let repository = build_repository(&config).await?;
    repository.run_migrations().await?;
    repository.health_check().await?;

    let state = AppState { repository };
    let app = build_router(state);
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
}
