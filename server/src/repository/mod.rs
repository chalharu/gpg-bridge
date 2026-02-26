use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use sqlx::{
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::config::{AppConfig, DatabaseKind, detect_database_kind};

mod postgres;
mod sqlite;

pub use postgres::PostgresRepository;
pub use sqlite::SqliteRepository;

pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A row in the `signing_keys` table.
#[derive(Debug, Clone)]
pub struct SigningKeyRow {
    pub kid: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_active: bool,
}

/// A row in the `clients` table.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub client_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub device_token: String,
    pub device_jwt_issued_at: String,
    pub public_keys: String,
    pub default_kid: String,
    pub gpg_keys: String,
}

/// A row in the `client_pairings` table.
#[derive(Debug, Clone)]
pub struct ClientPairingRow {
    pub client_id: String,
    pub pairing_id: String,
    pub client_jwt_issued_at: String,
}

/// A row in the `requests` table (subset for auth).
#[derive(Debug, Clone)]
pub struct RequestRow {
    pub request_id: String,
    pub status: String,
    pub daemon_public_key: String,
}

#[async_trait]
pub trait SignatureRepository: Send + Sync + std::fmt::Debug {
    async fn run_migrations(&self) -> anyhow::Result<()>;
    async fn health_check(&self) -> anyhow::Result<()>;
    fn backend_name(&self) -> &'static str;

    // ---- signing_keys operations ----

    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()>;
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool>;

    /// Delete signing keys whose `expires_at` is before `now`.
    ///
    /// `now` must be an RFC 3339 timestamp with a `+00:00` suffix
    /// (e.g. `"2025-01-01T00:00:00+00:00"`).  The comparison is performed
    /// as a lexicographic string comparison in the database, so a consistent
    /// format is required for correct behaviour.
    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64>;

    // ---- clients operations ----

    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>>;
    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()>;
    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool>;
    async fn client_by_device_token(&self, device_token: &str)
    -> anyhow::Result<Option<ClientRow>>;
    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()>;
    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;

    // ---- client_pairings operations ----

    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>>;

    // ---- requests operations ----

    async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>>;

    // ---- jtis operations ----

    /// Store a JTI for replay prevention. Returns `true` if newly inserted,
    /// `false` if the JTI already exists.
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;

    /// Delete JTIs whose `expired` timestamp is before `now`.
    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64>;
}

async fn build_postgres_repository(
    config: &AppConfig,
) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
        .connect(&config.database_url)
        .await
        .context("failed to connect postgres pool")?;

    Ok(Arc::new(PostgresRepository { pool }))
}

async fn build_sqlite_repository(
    config: &AppConfig,
) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let options = config
        .database_url
        .parse::<SqliteConnectOptions>()
        .context("failed to parse sqlite connection options")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
        .connect_with(options)
        .await
        .context("failed to connect sqlite pool")?;

    Ok(Arc::new(SqliteRepository { pool }))
}

pub async fn build_repository(config: &AppConfig) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    match detect_database_kind(&config.database_url)? {
        DatabaseKind::Postgres => build_postgres_repository(config).await,
        DatabaseKind::Sqlite => build_sqlite_repository(config).await,
    }
}
