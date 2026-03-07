use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, Encode, Executor, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::JtiRepository;

#[async_trait]
impl<T, DB> JtiRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
{
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expired)
        .execute(self.pool())
        .await
        .context("failed to store jti")?;
        Ok(T::rows_affected(&result) > 0)
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
            .bind(now)
            .execute(self.pool())
            .await
            .context("failed to delete expired jtis")?;
        Ok(T::rows_affected(&result))
    }
}
