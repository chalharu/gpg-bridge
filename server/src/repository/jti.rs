use async_trait::async_trait;

#[async_trait]
pub trait JtiRepository: Send + Sync {
    /// Store a JTI for replay prevention. Returns `true` if newly inserted,
    /// `false` if the JTI already exists.
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;

    /// Delete JTIs whose `expired` timestamp is before `now`.
    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64>;
}
