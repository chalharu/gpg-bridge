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
