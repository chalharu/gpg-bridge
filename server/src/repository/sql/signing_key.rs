use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, Encode, Executor, FromRow, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::{SigningKeyRepository, SigningKeyRow};

#[async_trait]
impl<T, DB> SigningKeyRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
    for<'q> bool: Encode<'q, DB> + Type<DB>,
    for<'r> SigningKeySqlRow: FromRow<'r, DB::Row>,
{
    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, private_key, public_key, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(key.kid.as_str())
        .bind(key.private_key.as_str())
        .bind(key.public_key.as_str())
        .bind(key.created_at.as_str())
        .bind(key.expires_at.as_str())
        .bind(key.is_active)
        .execute(self.pool())
        .await
        .context("failed to store signing key")?;
        Ok(())
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SigningKeySqlRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await
        .context("failed to get active signing key")?;
        Ok(row.map(Into::into))
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SigningKeySqlRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
        )
        .bind(kid)
        .fetch_optional(self.pool())
        .await
        .context("failed to get signing key by kid")?;
        Ok(row.map(Into::into))
    }

    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE signing_keys SET is_active = FALSE WHERE kid = $1")
            .bind(kid)
            .execute(self.pool())
            .await
            .context("failed to retire signing key")?;
        Ok(T::rows_affected(&result) > 0)
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM signing_keys WHERE expires_at < $1")
            .bind(now)
            .execute(self.pool())
            .await
            .context("failed to delete expired signing keys")?;
        Ok(T::rows_affected(&result))
    }
}

#[derive(sqlx::FromRow)]
struct SigningKeySqlRow {
    kid: String,
    private_key: String,
    public_key: String,
    created_at: String,
    expires_at: String,
    is_active: bool,
}

impl From<SigningKeySqlRow> for SigningKeyRow {
    fn from(row: SigningKeySqlRow) -> Self {
        Self {
            kid: row.kid,
            private_key: row.private_key,
            public_key: row.public_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            is_active: row.is_active,
        }
    }
}
