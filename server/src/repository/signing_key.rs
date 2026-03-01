use async_trait::async_trait;

/// A row in the `signing_keys` table.
#[derive(Debug, Clone)]
pub struct SigningKeyRow {
    pub kid: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_active: bool,
}

#[async_trait]
pub trait SigningKeyRepository: Send + Sync {
    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()>;
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool>;

    /// Delete signing keys whose `expires_at` is before `now`.
    ///
    /// `now` must be an RFC 3339 timestamp with a `+00:00` suffix
    /// (e.g. `"2025-01-01T00:00:00+00:00"`).  The comparison is performed
    /// as a lexicographic string comparison in the database, so a consistent
    /// format is required for correct behaviour.
    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64>;
}
