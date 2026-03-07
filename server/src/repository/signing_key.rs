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

macro_rules! impl_signing_key_repository {
    ($repo_ty:ty, $row_ty:ty) => {
        #[async_trait::async_trait]
        impl crate::repository::SigningKeyRepository for $repo_ty {
            async fn store_signing_key(
                &self,
                key: &crate::repository::SigningKeyRow,
            ) -> anyhow::Result<()> {
                sqlx::query(
                    "INSERT INTO signing_keys (kid, private_key, public_key, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&key.kid)
                .bind(&key.private_key)
                .bind(&key.public_key)
                .bind(&key.created_at)
                .bind(&key.expires_at)
                .bind(key.is_active)
                .execute(&self.pool)
                .await
                .context("failed to store signing key")?;
                Ok(())
            }

            async fn get_active_signing_key(
                &self,
            ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
                let row = sqlx::query_as::<_, $row_ty>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
                )
                .fetch_optional(&self.pool)
                .await
                .context("failed to get active signing key")?;
                Ok(row.map(Into::into))
            }

            async fn get_signing_key_by_kid(
                &self,
                kid: &str,
            ) -> anyhow::Result<Option<crate::repository::SigningKeyRow>> {
                let row = sqlx::query_as::<_, $row_ty>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
                )
                .bind(kid)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get signing key by kid")?;
                Ok(row.map(Into::into))
            }

            async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
                let result = sqlx::query("UPDATE signing_keys SET is_active = FALSE WHERE kid = $1")
                    .bind(kid)
                    .execute(&self.pool)
                    .await
                    .context("failed to retire signing key")?;
                Ok(result.rows_affected() > 0)
            }

            async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM signing_keys WHERE expires_at < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired signing keys")?;
                Ok(result.rows_affected())
            }
        }
    };
}

pub(crate) use impl_signing_key_repository;
