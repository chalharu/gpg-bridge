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
    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64>;
}

pub async fn build_repository(config: &AppConfig) -> anyhow::Result<Arc<dyn SignatureRepository>> {
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
    }
}
