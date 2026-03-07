use anyhow::Context;
use async_trait::async_trait;

use super::PostgresRepository;
use crate::repository::JtiRepository;

#[async_trait]
impl JtiRepository for PostgresRepository {
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        let result = execute_query!(
            &self.pool,
            "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
            "failed to store jti",
            jti,
            expired,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        let result = execute_query!(
            &self.pool,
            "DELETE FROM jtis WHERE expired < $1",
            "failed to delete expired jtis",
            now,
        )?;
        Ok(result.rows_affected())
    }
}
