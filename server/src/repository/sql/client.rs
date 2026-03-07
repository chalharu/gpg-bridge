use async_trait::async_trait;

use super::ClientRecord;
use crate::repository::{ClientRepository, ClientRow};

#[async_trait]
pub(super) trait CommonClientLookupRepository: Send + Sync {
    async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>>;
    async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool>;
    async fn client_by_device_token_common(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>>;
}

#[async_trait]
pub(super) trait CommonClientLifecycleRepository: Send + Sync {
    async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()>;
    async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()>;
}

#[async_trait]
pub(super) trait CommonClientUpdateRepository: Send + Sync {
    async fn update_client_device_token_common(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_default_kid_common(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_device_jwt_issued_at_common(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_public_keys_common(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;
    async fn update_client_gpg_keys_common(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;
}

pub(super) trait CommonClientRepository:
    CommonClientLookupRepository + CommonClientLifecycleRepository + CommonClientUpdateRepository
{
}

impl<T> CommonClientRepository for T where
    T: CommonClientLookupRepository
        + CommonClientLifecycleRepository
        + CommonClientUpdateRepository
{
}

mod lifecycle;
mod lookup;
mod update;

#[async_trait]
impl<T> ClientRepository for T
where
    T: CommonClientRepository + Send + Sync,
{
    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        self.get_client_by_id_common(client_id).await
    }

    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        self.create_client_common(row).await
    }

    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        self.client_exists_common(client_id).await
    }

    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        self.client_by_device_token_common(device_token).await
    }

    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_client_device_token_common(client_id, device_token, updated_at)
            .await
    }

    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_client_default_kid_common(client_id, default_kid, updated_at)
            .await
    }

    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        self.delete_client_common(client_id).await
    }

    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_device_jwt_issued_at_common(client_id, issued_at, updated_at)
            .await
    }

    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_public_keys_common(
            client_id,
            public_keys,
            default_kid,
            updated_at,
            expected_updated_at,
        )
        .await
    }

    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_gpg_keys_common(client_id, gpg_keys, updated_at, expected_updated_at)
            .await
    }
}

impl From<ClientRecord> for ClientRow {
    fn from(record: ClientRecord) -> Self {
        Self {
            client_id: record.client_id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            device_token: record.device_token,
            device_jwt_issued_at: record.device_jwt_issued_at,
            public_keys: record.public_keys,
            default_kid: record.default_kid,
            gpg_keys: record.gpg_keys,
        }
    }
}
