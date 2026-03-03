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
