use async_trait::async_trait;

#[async_trait]
pub trait CleanupRepository: Send + Sync {
    /// Delete clients that have no pairings and were created before `cutoff`.
    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64>;

    /// Delete clients whose `device_jwt_issued_at` is before `cutoff`.
    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64>;

    /// Remove client_pairings whose `client_jwt_issued_at` is before
    /// `cutoff`, then delete any clients that have no remaining pairings.
    /// Returns the total number of pairings removed.
    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64>;
}

macro_rules! impl_cleanup_repository {
    ($repo_ty:ty) => {
        #[async_trait::async_trait]
        impl crate::repository::CleanupRepository for $repo_ty {
            async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
                let result = sqlx::query(
                    "DELETE FROM clients WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id)",
                )
                .bind(cutoff)
                .execute(&self.pool)
                .await
                .context("failed to delete unpaired clients")?;
                Ok(result.rows_affected())
            }

            async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM clients WHERE device_jwt_issued_at < $1")
                    .bind(cutoff)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired device_jwt clients")?;
                Ok(result.rows_affected())
            }

            async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .context("failed to begin transaction")?;

                let del = sqlx::query("DELETE FROM client_pairings WHERE client_jwt_issued_at < $1")
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete expired client_jwt pairings")?;
                let removed = del.rows_affected();

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
    };
}

pub(crate) use impl_cleanup_repository;
