use anyhow::Context;
use async_trait::async_trait;

use super::SigningKeyRecord;
use crate::repository::{SigningKeyRepository, SigningKeyRow};

#[async_trait]
trait CommonSigningKeyRepository: Send + Sync {
    async fn store_signing_key_common(&self, key: &SigningKeyRow) -> anyhow::Result<()>;
    async fn get_active_signing_key_common(&self) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn get_signing_key_by_kid_common(
        &self,
        kid: &str,
    ) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn retire_signing_key_common(&self, kid: &str) -> anyhow::Result<bool>;
    async fn delete_expired_signing_keys_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> SigningKeyRepository for T
where
    T: CommonSigningKeyRepository + Send + Sync,
{
    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        self.store_signing_key_common(key).await
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        self.get_active_signing_key_common().await
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        self.get_signing_key_by_kid_common(kid).await
    }

    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
        self.retire_signing_key_common(kid).await
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_signing_keys_common(now).await
    }
}

impl From<SigningKeyRecord> for SigningKeyRow {
    fn from(record: SigningKeyRecord) -> Self {
        Self {
            kid: record.kid,
            private_key: record.private_key,
            public_key: record.public_key,
            created_at: record.created_at,
            expires_at: record.expires_at,
            is_active: record.is_active,
        }
    }
}

impl_for_sql_backends!(CommonSigningKeyRepository {
    async fn store_signing_key_common(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        execute_query!(
            "INSERT INTO signing_keys (kid, private_key, public_key, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
            &self.pool,
            "failed to store signing key",
            &key.kid,
            &key.private_key,
            &key.public_key,
            &key.created_at,
            &key.expires_at,
            key.is_active,
        )?;
        Ok(())
    }

    async fn get_active_signing_key_common(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = fetch_optional_as!(
            SigningKeyRecord,
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
            &self.pool,
            "failed to get active signing key",
        )?;
        Ok(row.map(Into::into))
    }

    async fn get_signing_key_by_kid_common(
        &self,
        kid: &str,
    ) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = fetch_optional_as!(
            SigningKeyRecord,
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
            &self.pool,
            "failed to get signing key by kid",
            kid,
        )?;
        Ok(row.map(Into::into))
    }

    async fn retire_signing_key_common(&self, kid: &str) -> anyhow::Result<bool> {
        let result = execute_query!(
            "UPDATE signing_keys SET is_active = FALSE WHERE kid = $1",
            &self.pool,
            "failed to retire signing key",
            kid,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_signing_keys_common(&self, now: &str) -> anyhow::Result<u64> {
        let result = execute_query!(
            "DELETE FROM signing_keys WHERE expires_at < $1",
            &self.pool,
            "failed to delete expired signing keys",
            now,
        )?;
        Ok(result.rows_affected())
    }
});
