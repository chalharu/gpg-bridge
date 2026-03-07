use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use sqlx::{
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::config::{AppConfig, DatabaseKind, detect_database_kind};

mod audit_log;
mod cleanup;
mod client;
mod client_pairing;
mod jti;
mod pairing;
mod postgres;
mod request;
mod signing_key;
pub(crate) mod sqlite;

#[cfg(test)]
mod tests;

pub use audit_log::{AuditLogRepository, AuditLogRow};
pub use cleanup::CleanupRepository;
pub use client::{ClientRepository, ClientRow};
pub use client_pairing::{ClientPairingRepository, ClientPairingRow};
pub use jti::JtiRepository;
pub use pairing::{PairingRepository, PairingRow};
pub use postgres::PostgresRepository;
pub use request::{CreateRequestRow, FullRequestRow, RequestRepository, RequestRow};
pub use signing_key::{SigningKeyRepository, SigningKeyRow};
pub use sqlite::SqliteRepository;

pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[async_trait]
pub trait SignatureRepository:
    SigningKeyRepository
    + ClientRepository
    + ClientPairingRepository
    + PairingRepository
    + RequestRepository
    + AuditLogRepository
    + JtiRepository
    + CleanupRepository
    + Send
    + Sync
    + std::fmt::Debug
{
    async fn run_migrations(&self) -> anyhow::Result<()>;
    async fn health_check(&self) -> anyhow::Result<()>;
    fn backend_name(&self) -> &'static str;
}

macro_rules! impl_signature_repository {
    ($repo_ty:ty, $backend_name:literal, $migration_error:literal) => {
        #[async_trait::async_trait]
        impl crate::repository::SignatureRepository for $repo_ty {
            async fn run_migrations(&self) -> anyhow::Result<()> {
                crate::repository::MIGRATOR
                    .run(&self.pool)
                    .await
                    .context($migration_error)
            }

            async fn health_check(&self) -> anyhow::Result<()> {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(&self.pool)
                    .await
                    .context(concat!($backend_name, " health check failed"))?;

                Ok(())
            }

            fn backend_name(&self) -> &'static str {
                $backend_name
            }
        }
    };
}

pub(crate) use impl_signature_repository;

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
