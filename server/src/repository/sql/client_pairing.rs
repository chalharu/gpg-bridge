use async_trait::async_trait;

use super::ClientPairingRecord;
use crate::repository::{ClientPairingRepository, ClientPairingRow};

#[async_trait]
pub(super) trait CommonClientPairingQueryRepository: Send + Sync {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>>;
}

#[async_trait]
pub(super) trait CommonClientPairingMutationRepository: Send + Sync {
    async fn create_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()>;
    async fn delete_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool>;
    async fn update_client_jwt_issued_at_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
pub(super) trait CommonClientPairingCleanupRepository: Send + Sync {
    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)>;
}

pub(super) trait CommonClientPairingRepository:
    CommonClientPairingQueryRepository
    + CommonClientPairingMutationRepository
    + CommonClientPairingCleanupRepository
{
}

impl<T> CommonClientPairingRepository for T where
    T: CommonClientPairingQueryRepository
        + CommonClientPairingMutationRepository
        + CommonClientPairingCleanupRepository
{
}

mod cleanup;
mod mutation;
mod query;

#[async_trait]
impl<T> ClientPairingRepository for T
where
    T: CommonClientPairingRepository + Send + Sync,
{
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        self.get_client_pairings_common(client_id).await
    }

    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        self.create_client_pairing_common(client_id, pairing_id, client_jwt_issued_at)
            .await
    }

    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        self.delete_client_pairing_common(client_id, pairing_id)
            .await
    }

    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        self.delete_client_pairing_and_cleanup_common(client_id, pairing_id)
            .await
    }

    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_jwt_issued_at_common(client_id, pairing_id, issued_at)
            .await
    }
}

impl From<ClientPairingRecord> for ClientPairingRow {
    fn from(record: ClientPairingRecord) -> Self {
        Self {
            client_id: record.client_id,
            pairing_id: record.pairing_id,
            client_jwt_issued_at: record.client_jwt_issued_at,
        }
    }
}
