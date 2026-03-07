use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, Executor, IntoArguments, Pool, migrate::Migrate};

use super::DbRepository;
use crate::repository::{
    AuditLogRepository, CleanupRepository, ClientPairingRepository, ClientRepository,
    JtiRepository, MIGRATOR, PairingRepository, RequestRepository, SignatureRepository,
    SigningKeyRepository,
};

#[async_trait]
impl<T, DB> SignatureRepository for T
where
    T: DbRepository<Database = DB>
        + SigningKeyRepository
        + ClientRepository
        + ClientPairingRepository
        + PairingRepository
        + RequestRepository
        + AuditLogRepository
        + JtiRepository
        + CleanupRepository
        + Send
        + Sync
        + std::fmt::Debug,
    DB: Database,
    DB::Connection: Migrate,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
{
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(self.pool())
            .await
            .with_context(|| format!("failed to run {} migrations", self.database_backend_name()))
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1")
            .execute(self.pool())
            .await
            .with_context(|| format!("{} health check failed", self.database_backend_name()))?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        self.database_backend_name()
    }
}
