use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use clap::Parser;
use serde::Serialize;
use sqlx::{
    PgPool, SqlitePool,
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

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
    db_max_connections: u32,
    db_min_connections: u32,
    db_acquire_timeout_seconds: u64,
    log_level: String,
    log_format: String,
}

#[derive(Debug, Clone)]
struct AppState {
    repository: Arc<dyn SignatureRepository>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseKind {
    Postgres,
    Sqlite,
}

fn detect_database_kind(database_url: &str) -> anyhow::Result<DatabaseKind> {
    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        return Ok(DatabaseKind::Postgres);
    }

    if database_url.starts_with("sqlite:") {
        return Ok(DatabaseKind::Sqlite);
    }

    Err(anyhow!(
        "unsupported SERVER_DATABASE_URL scheme. expected postgres://, postgresql://, or sqlite:, got '{database_url}'"
    ))
}

#[async_trait]
trait SignatureRepository: Send + Sync + std::fmt::Debug {
    async fn run_migrations(&self) -> anyhow::Result<()>;
    async fn health_check(&self) -> anyhow::Result<()>;
    fn backend_name(&self) -> &'static str;
}

#[derive(Debug, Clone)]
struct PostgresRepository {
    pool: PgPool,
}

#[async_trait]
impl SignatureRepository for PostgresRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run postgres migrations")
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("postgres health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }
}

#[derive(Debug, Clone)]
struct SqliteRepository {
    pool: SqlitePool,
}

#[async_trait]
impl SignatureRepository for SqliteRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run sqlite migrations")
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("sqlite health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }
}

async fn build_repository(config: &AppConfig) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let kind = detect_database_kind(&config.database_url)?;

    match kind {
        DatabaseKind::Postgres => {
            let pool = PgPoolOptions::new()
                .max_connections(config.db_max_connections)
                .min_connections(config.db_min_connections)
                .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
                .connect(&config.database_url)
                .await
                .context("failed to connect postgres pool")?;

            Ok(Arc::new(PostgresRepository { pool }))
        }
        DatabaseKind::Sqlite => {
            let options = config
                .database_url
                .parse::<SqliteConnectOptions>()
                .context("failed to parse sqlite connection options")?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal);

            let pool = SqlitePoolOptions::new()
                .max_connections(config.db_max_connections)
                .min_connections(config.db_min_connections)
                .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
                .connect_with(options)
                .await
                .context("failed to connect sqlite pool")?;

            Ok(Arc::new(SqliteRepository { pool }))
        }
    }
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

        let db_max_connections_raw =
            lookup("SERVER_DB_MAX_CONNECTIONS").unwrap_or_else(|| "20".to_owned());
        let db_max_connections: u32 = db_max_connections_raw.parse().with_context(|| {
            format!("SERVER_DB_MAX_CONNECTIONS must be a valid u32, got '{db_max_connections_raw}'")
        })?;

        let db_min_connections_raw =
            lookup("SERVER_DB_MIN_CONNECTIONS").unwrap_or_else(|| "1".to_owned());
        let db_min_connections: u32 = db_min_connections_raw.parse().with_context(|| {
            format!("SERVER_DB_MIN_CONNECTIONS must be a valid u32, got '{db_min_connections_raw}'")
        })?;

        let db_acquire_timeout_seconds_raw =
            lookup("SERVER_DB_ACQUIRE_TIMEOUT_SECONDS").unwrap_or_else(|| "5".to_owned());
        let db_acquire_timeout_seconds: u64 = db_acquire_timeout_seconds_raw.parse().with_context(|| {
            format!(
                "SERVER_DB_ACQUIRE_TIMEOUT_SECONDS must be a valid u64, got '{db_acquire_timeout_seconds_raw}'"
            )
        })?;

        let log_level = lookup("SERVER_LOG_LEVEL").unwrap_or_else(|| "info".to_owned());
        let log_format = lookup("SERVER_LOG_FORMAT").unwrap_or_else(|| "plain".to_owned());

        Ok(Self {
            server_host,
            server_port,
            database_url,
            db_max_connections,
            db_min_connections,
            db_acquire_timeout_seconds,
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
    database_backend: &'static str,
    database_status: &'static str,
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<HealthResponse> {
    let database_status = if state.repository.health_check().await.is_ok() {
        "ok"
    } else {
        "error"
    };

    Json(HealthResponse {
        status: "ok",
        database_backend: state.repository.backend_name(),
        database_status,
    })
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

    let request_id_header = axum::http::header::HeaderName::from_static("x-request-id");

    let state = AppState {
        repository: Arc::clone(&repository),
    };
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

    info!(database_backend = %repository.backend_name(), "database initialized");
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
        assert_eq!(config.db_max_connections, 20);
        assert_eq!(config.db_min_connections, 1);
        assert_eq!(config.db_acquire_timeout_seconds, 5);
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
        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "sqlite::memory:".to_owned(),
            db_max_connections: 4,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "plain".to_owned(),
        };
        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();

        let state = AppState { repository };

        let Json(response) = health(axum::extract::State(state)).await;

        assert_eq!(response.status, "ok");
        assert_eq!(response.database_backend, "sqlite");
        assert_eq!(response.database_status, "ok");
    }

    #[test]
    fn init_tracing_rejects_invalid_log_format() {
        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "postgres://localhost:5432/gpg_bridge".to_owned(),
            db_max_connections: 20,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "invalid".to_owned(),
        };

        let result = init_tracing(&config);
        assert!(result.is_err());
    }

    #[test]
    fn detect_database_kind_supports_postgres() {
        let kind = detect_database_kind("postgres://localhost:5432/gpg_bridge").unwrap();
        assert_eq!(kind, DatabaseKind::Postgres);
    }

    #[test]
    fn detect_database_kind_supports_sqlite() {
        let kind = detect_database_kind("sqlite://tmp/test.db").unwrap();
        assert_eq!(kind, DatabaseKind::Sqlite);
    }

    #[test]
    fn detect_database_kind_rejects_unknown_scheme() {
        let result = detect_database_kind("mysql://localhost:3306/gpg_bridge");
        assert!(result.is_err());
    }
}
