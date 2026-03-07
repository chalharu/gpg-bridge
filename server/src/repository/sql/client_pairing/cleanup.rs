use anyhow::Context;
use async_trait::async_trait;

use super::CommonClientPairingCleanupRepository;

#[async_trait]
impl CommonClientPairingCleanupRepository for crate::repository::PostgresRepository {
    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;
        let deleted =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = deleted.rows_affected() > 0;
        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
            )
            .bind(client_id)
            .fetch_one(&mut *tx)
            .await
            .context("failed to count remaining pairings")?;
            if remaining == 0 {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete client")?;
                client_deleted = true;
            }
        }
        tx.commit().await.context("failed to commit transaction")?;
        Ok((pairing_deleted, client_deleted))
    }
}

#[async_trait]
impl CommonClientPairingCleanupRepository for crate::repository::SqliteRepository {
    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;
        let deleted =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = deleted.rows_affected() > 0;
        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
            )
            .bind(client_id)
            .fetch_one(&mut *tx)
            .await
            .context("failed to count remaining pairings")?;
            if remaining == 0 {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete client")?;
                client_deleted = true;
            }
        }
        tx.commit().await.context("failed to commit transaction")?;
        Ok((pairing_deleted, client_deleted))
    }
}
