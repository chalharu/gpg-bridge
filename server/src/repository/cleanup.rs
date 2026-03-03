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
