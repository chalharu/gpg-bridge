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

#[async_trait]
impl CommonJtiRepository for crate::repository::PostgresRepository {
    async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
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

    async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired jtis")?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl CommonJtiRepository for crate::repository::SqliteRepository {
    async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
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

    async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired jtis")?;
        Ok(result.rows_affected())
    }
}
