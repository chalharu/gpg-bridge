use async_trait::async_trait;

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

#[async_trait]
pub trait ClientRepository: Send + Sync {
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

    /// Update public_keys and default_kid for a client in one query.
    ///
    /// Uses optimistic locking: the update only succeeds if the current
    /// `updated_at` matches `expected_updated_at`.  Returns `true` if the
    /// row was updated, `false` on a concurrent modification.
    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;

    /// Update gpg_keys for a client.
    ///
    /// Uses optimistic locking: the update only succeeds if the current
    /// `updated_at` matches `expected_updated_at`.  Returns `true` if the
    /// row was updated, `false` on a concurrent modification.
    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;
}

macro_rules! impl_client_repository {
    ($repo_ty:ty, $row_ty:ty, $count_ty:ty, $count_map:expr) => {
        #[async_trait::async_trait]
        impl crate::repository::ClientRepository for $repo_ty {
            async fn get_client_by_id(
                &self,
                client_id: &str,
            ) -> anyhow::Result<Option<crate::repository::ClientRow>> {
                let row = sqlx::query_as::<_, $row_ty>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by id")?;
                Ok(row.map(Into::into))
            }

            async fn create_client(&self, row: &crate::repository::ClientRow) -> anyhow::Result<()> {
                sqlx::query(
                    "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(&row.client_id)
                .bind(&row.created_at)
                .bind(&row.updated_at)
                .bind(&row.device_token)
                .bind(&row.device_jwt_issued_at)
                .bind(&row.public_keys)
                .bind(&row.default_kid)
                .bind(&row.gpg_keys)
                .execute(&self.pool)
                .await
                .context("failed to create client")?;
                Ok(())
            }

            async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
                let count: $count_ty =
                    sqlx::query_scalar::<_, $count_ty>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                        .bind(client_id)
                        .fetch_one(&self.pool)
                        .await
                        .context("failed to check client existence")?;
                Ok(($count_map)(count) > 0)
            }

            async fn client_by_device_token(
                &self,
                device_token: &str,
            ) -> anyhow::Result<Option<crate::repository::ClientRow>> {
                let row = sqlx::query_as::<_, $row_ty>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
                )
                .bind(device_token)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by device_token")?;
                Ok(row.map(Into::into))
            }

            async fn update_client_device_token(
                &self,
                client_id: &str,
                device_token: &str,
                updated_at: &str,
            ) -> anyhow::Result<()> {
                sqlx::query("UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3")
                    .bind(device_token)
                    .bind(updated_at)
                    .bind(client_id)
                    .execute(&self.pool)
                    .await
                    .context("failed to update client device_token")?;
                Ok(())
            }

            async fn update_client_default_kid(
                &self,
                client_id: &str,
                default_kid: &str,
                updated_at: &str,
            ) -> anyhow::Result<()> {
                sqlx::query("UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3")
                    .bind(default_kid)
                    .bind(updated_at)
                    .bind(client_id)
                    .execute(&self.pool)
                    .await
                    .context("failed to update client default_kid")?;
                Ok(())
            }

            async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete client")?;
                Ok(())
            }

            async fn update_device_jwt_issued_at(
                &self,
                client_id: &str,
                issued_at: &str,
                updated_at: &str,
            ) -> anyhow::Result<()> {
                sqlx::query(
                    "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
                )
                .bind(issued_at)
                .bind(updated_at)
                .bind(client_id)
                .execute(&self.pool)
                .await
                .context("failed to update device_jwt_issued_at")?;
                Ok(())
            }

            async fn update_client_public_keys(
                &self,
                client_id: &str,
                public_keys: &str,
                default_kid: &str,
                updated_at: &str,
                expected_updated_at: &str,
            ) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "UPDATE clients SET public_keys = $1, default_kid = $2, updated_at = $3 WHERE client_id = $4 AND updated_at = $5",
                )
                .bind(public_keys)
                .bind(default_kid)
                .bind(updated_at)
                .bind(client_id)
                .bind(expected_updated_at)
                .execute(&self.pool)
                .await
                .context("failed to update client public_keys")?;
                Ok(result.rows_affected() > 0)
            }

            async fn update_client_gpg_keys(
                &self,
                client_id: &str,
                gpg_keys: &str,
                updated_at: &str,
                expected_updated_at: &str,
            ) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "UPDATE clients SET gpg_keys = $1, updated_at = $2 WHERE client_id = $3 AND updated_at = $4",
                )
                .bind(gpg_keys)
                .bind(updated_at)
                .bind(client_id)
                .bind(expected_updated_at)
                .execute(&self.pool)
                .await
                .context("failed to update client gpg_keys")?;
                Ok(result.rows_affected() > 0)
            }
        }
    };
}

pub(crate) use impl_client_repository;
