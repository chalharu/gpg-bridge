use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, Encode, Executor, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::CleanupRepository;

#[async_trait]
impl<T, DB> CleanupRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'c> &'c mut DB::Connection: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
{
    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM clients WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id)",
        )
        .bind(cutoff)
        .execute(self.pool())
        .await
        .context("failed to delete unpaired clients")?;
        Ok(T::rows_affected(&result))
    }

    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM clients WHERE device_jwt_issued_at < $1")
            .bind(cutoff)
            .execute(self.pool())
            .await
            .context("failed to delete expired device_jwt clients")?;
        Ok(T::rows_affected(&result))
    }

    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .context("failed to begin transaction")?;

        let del = sqlx::query("DELETE FROM client_pairings WHERE client_jwt_issued_at < $1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .context("failed to delete expired client_jwt pairings")?;
        let removed = T::rows_affected(&del);

        sqlx::query(
            "DELETE FROM clients WHERE NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id) AND NOT EXISTS (SELECT 1 FROM pairings WHERE pairings.client_id = clients.client_id)",
        )
        .execute(&mut *tx)
        .await
        .context("failed to delete orphaned clients")?;

        tx.commit().await.context("failed to commit transaction")?;
        Ok(removed)
    }
}
