use async_trait::async_trait;

#[async_trait]
pub trait JtiRepository: Send + Sync {
    /// Store a JTI for replay prevention. Returns `true` if newly inserted,
    /// `false` if the JTI already exists.
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;

    /// Delete JTIs whose `expired` timestamp is before `now`.
    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64>;
}

macro_rules! impl_jti_repository {
    ($repo_ty:ty) => {
        #[async_trait::async_trait]
        impl crate::repository::JtiRepository for $repo_ty {
            async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
                let result = sqlx::query(
                    "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
                )
                .bind(jti)
                .bind(expired)
                .execute(&self.pool)
                .await
                .context("failed to store jti")?;
                Ok(result.rows_affected() > 0)
            }

            async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired jtis")?;
                Ok(result.rows_affected())
            }
        }
    };
}

pub(crate) use impl_jti_repository;
