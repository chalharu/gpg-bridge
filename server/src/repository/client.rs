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
