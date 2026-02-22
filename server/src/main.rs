use std::net::SocketAddr;

use axum::{Json, Router, routing::get};
use clap::Parser;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-server")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

fn parse_socket_addr(host: &str, port: u16) -> Result<SocketAddr, std::net::AddrParseError> {
    format!("{}:{}", host, port).parse()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = parse_socket_addr(&cli.host, cli.port)?;

    let app = Router::new().route("/", get(health));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_are_applied() {
        let cli = Cli::parse_from(["gpg-bridge-server"]);

        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 3000);
    }

    #[test]
    fn cli_custom_values_are_applied() {
        let cli = Cli::parse_from([
            "gpg-bridge-server",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ]);

        assert_eq!(cli.host, "0.0.0.0");
        assert_eq!(cli.port, 8080);
    }

    #[test]
    fn parse_socket_addr_returns_error_for_invalid_host() {
        let result = parse_socket_addr("invalid host", 3000);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_returns_ok_status() {
        let Json(response) = health().await;

        assert_eq!(response.status, "ok");
    }
}
