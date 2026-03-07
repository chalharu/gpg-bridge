use anyhow::Context;
use sqlx::{Database, Encode, Executor, IntoArguments, Pool, Type, any::AnyQueryResult};

use super::DbRepository;
use crate::repository::JtiRepository;

async fn store_jti<Repository, DB>(
    repository: &Repository,
    jti: &str,
    expired: &str,
) -> anyhow::Result<bool>
where
    Repository: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'q> DB::Arguments<'q>: IntoArguments<'q, DB>,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'c> &'c str: Type<DB> + Encode<'c, DB>,
    AnyQueryResult: From<DB::QueryResult>,
{
    let result =
        sqlx::query("INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING")
            .bind(jti)
            .bind(expired)
            .execute(repository.pool())
            .await
            .context("failed to store jti")?;
    Ok(AnyQueryResult::from(result).rows_affected() > 0)
}

async fn delete_expired_jtis<Repository, DB>(
    repository: &Repository,
    now: &str,
) -> anyhow::Result<u64>
where
    Repository: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'q> DB::Arguments<'q>: IntoArguments<'q, DB>,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'c> &'c str: Type<DB> + Encode<'c, DB>,
    AnyQueryResult: From<DB::QueryResult>,
{
    let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
        .bind(now)
        .execute(repository.pool())
        .await
        .context("failed to delete expired jtis")?;
    Ok(AnyQueryResult::from(result).rows_affected())
}

impl_for_sql_backends!(JtiRepository {
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        store_jti(self, jti, expired).await
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        delete_expired_jtis(self, now).await
    }
});
