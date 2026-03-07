use anyhow::Context;
use async_trait::async_trait;

use crate::repository::JtiRepository;

#[async_trait]
trait CommonJtiRepository: Send + Sync {
    async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;
    async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> JtiRepository for T
where
    T: CommonJtiRepository + Send + Sync,
{
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        self.store_jti_common(jti, expired).await
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_jtis_common(now).await
    }
}

impl_for_sql_backends!(CommonJtiRepository {
    async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        let result = execute_query!(
            "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
            &self.pool,
            "failed to store jti",
            jti,
            expired,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64> {
        let result = execute_query!(
            "DELETE FROM jtis WHERE expired < $1",
            &self.pool,
            "failed to delete expired jtis",
            now,
        )?;
        Ok(result.rows_affected())
    }
});
