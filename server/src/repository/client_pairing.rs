use async_trait::async_trait;

/// A row in the `client_pairings` table.
#[derive(Debug, Clone)]
pub struct ClientPairingRow {
    pub client_id: String,
    pub pairing_id: String,
    pub client_jwt_issued_at: String,
}

#[async_trait]
pub trait ClientPairingRepository: Send + Sync {
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>>;

    /// Add a client pairing entry.
    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()>;

    /// Remove a specific client pairing. Returns true if deleted.
    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool>;

    /// Atomically delete a client pairing and, if no pairings remain, delete
    /// the client record.  Returns `(pairing_deleted, client_deleted)`.
    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)>;

    /// Update client_jwt_issued_at for a specific client pairing.
    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool>;
}

macro_rules! impl_client_pairing_repository {
    ($repo_ty:ty, $row_ty:ty, $count_ty:ty, $count_map:expr) => {
        #[async_trait::async_trait]
        impl crate::repository::ClientPairingRepository for $repo_ty {
            async fn get_client_pairings(
                &self,
                client_id: &str,
            ) -> anyhow::Result<Vec<crate::repository::ClientPairingRow>> {
                let rows = sqlx::query_as::<_, $row_ty>(
                    "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_all(&self.pool)
                .await
                .context("failed to get client pairings")?;
                Ok(rows.into_iter().map(Into::into).collect())
            }

            async fn create_client_pairing(
                &self,
                client_id: &str,
                pairing_id: &str,
                client_jwt_issued_at: &str,
            ) -> anyhow::Result<()> {
                sqlx::query(
                    "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ($1, $2, $3)",
                )
                .bind(client_id)
                .bind(pairing_id)
                .bind(client_jwt_issued_at)
                .execute(&self.pool)
                .await
                .context("failed to create client pairing")?;
                Ok(())
            }

            async fn delete_client_pairing(
                &self,
                client_id: &str,
                pairing_id: &str,
            ) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2",
                )
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to delete client pairing")?;
                Ok(result.rows_affected() > 0)
            }

            async fn delete_client_pairing_and_cleanup(
                &self,
                client_id: &str,
                pairing_id: &str,
            ) -> anyhow::Result<(bool, bool)> {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .context("failed to begin transaction")?;

                let del = sqlx::query(
                    "DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2",
                )
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
                let pairing_deleted = del.rows_affected() > 0;

                let mut client_deleted = false;
                if pairing_deleted {
                    let remaining: $count_ty = sqlx::query_scalar::<_, $count_ty>(
                        "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
                    )
                    .bind(client_id)
                    .fetch_one(&mut *tx)
                    .await
                    .context("failed to count remaining pairings")?;

                    if ($count_map)(remaining) == 0 {
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

            async fn update_client_jwt_issued_at(
                &self,
                client_id: &str,
                pairing_id: &str,
                issued_at: &str,
            ) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "UPDATE client_pairings SET client_jwt_issued_at = $1 WHERE client_id = $2 AND pairing_id = $3",
                )
                .bind(issued_at)
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to update client_jwt_issued_at")?;
                Ok(result.rows_affected() > 0)
            }
        }
    };
}

pub(crate) use impl_client_pairing_repository;
