use anyhow::Context;

use super::CommonClientPairingCleanupRepository;

impl_for_sql_backends!(CommonClientPairingCleanupRepository {
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
        let deleted = execute_query!(
            "DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2",
            &mut *tx,
            "failed to delete client pairing",
            client_id,
            pairing_id,
        )?;
        let pairing_deleted = deleted.rows_affected() > 0;
        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = fetch_one_scalar!(
                i64,
                "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
                &mut *tx,
                "failed to count remaining pairings",
                client_id,
            )?;
            if remaining == 0 {
                execute_query!(
                    "DELETE FROM clients WHERE client_id = $1",
                    &mut *tx,
                    "failed to delete client",
                    client_id,
                )?;
                client_deleted = true;
            }
        }
        tx.commit().await.context("failed to commit transaction")?;
        Ok((pairing_deleted, client_deleted))
    }
});
