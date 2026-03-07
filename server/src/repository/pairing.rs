use async_trait::async_trait;

/// A row in the `pairings` table.
#[derive(Debug, Clone)]
pub struct PairingRow {
    pub pairing_id: String,
    pub expired: String,
    pub client_id: Option<String>,
}

#[async_trait]
pub trait PairingRepository: Send + Sync {
    /// Create a pairing record (client_id = NULL).
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()>;

    /// Get a pairing record by ID.
    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>>;

    /// Consume a pairing: set client_id only if it is currently NULL.
    /// Returns true if updated (was unconsumed), false if already consumed.
    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool>;

    /// Count unconsumed pairings (client_id IS NULL and not yet expired).
    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64>;

    /// Delete expired pairings.
    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64>;
}

macro_rules! impl_pairing_repository {
    ($repo_ty:ty, $row_ty:ty, $count_ty:ty, $count_map:expr) => {
        #[async_trait::async_trait]
        impl crate::repository::PairingRepository for $repo_ty {
            async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
                sqlx::query("INSERT INTO pairings (pairing_id, expired) VALUES ($1, $2)")
                    .bind(pairing_id)
                    .bind(expired)
                    .execute(&self.pool)
                    .await
                    .context("failed to create pairing")?;
                Ok(())
            }

            async fn get_pairing_by_id(
                &self,
                pairing_id: &str,
            ) -> anyhow::Result<Option<crate::repository::PairingRow>> {
                let row = sqlx::query_as::<_, $row_ty>(
                    "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
                )
                .bind(pairing_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get pairing by id")?;
                Ok(row.map(Into::into))
            }

            async fn consume_pairing(
                &self,
                pairing_id: &str,
                client_id: &str,
            ) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "UPDATE pairings SET client_id = $1 WHERE pairing_id = $2 AND client_id IS NULL",
                )
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to consume pairing")?;
                Ok(result.rows_affected() > 0)
            }

            async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64> {
                let count: $count_ty = sqlx::query_scalar::<_, $count_ty>(
                    "SELECT COUNT(*) FROM pairings WHERE client_id IS NULL AND expired > $1",
                )
                .bind(now)
                .fetch_one(&self.pool)
                .await
                .context("failed to count unconsumed pairings")?;
                Ok(($count_map)(count))
            }

            async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM pairings WHERE expired < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired pairings")?;
                Ok(result.rows_affected())
            }
        }
    };
}

pub(crate) use impl_pairing_repository;
