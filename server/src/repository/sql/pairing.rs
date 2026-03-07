use anyhow::Context;
use async_trait::async_trait;
use sqlx::{ColumnIndex, Database, Decode, Encode, Executor, FromRow, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::{PairingRepository, PairingRow};

#[async_trait]
impl<T, DB> PairingRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
    for<'r> PairingSqlRow: FromRow<'r, DB::Row>,
    for<'r> T::Count: Decode<'r, DB> + Type<DB>,
    usize: ColumnIndex<DB::Row>,
{
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO pairings (pairing_id, expired) VALUES ($1, $2)")
            .bind(pairing_id)
            .bind(expired)
            .execute(self.pool())
            .await
            .context("failed to create pairing")?;
        Ok(())
    }

    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        let row = sqlx::query_as::<_, PairingSqlRow>(
            "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
        )
        .bind(pairing_id)
        .fetch_optional(self.pool())
        .await
        .context("failed to get pairing by id")?;
        Ok(row.map(Into::into))
    }

    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE pairings SET client_id = $1 WHERE pairing_id = $2 AND client_id IS NULL",
        )
        .bind(client_id)
        .bind(pairing_id)
        .execute(self.pool())
        .await
        .context("failed to consume pairing")?;
        Ok(T::rows_affected(&result) > 0)
    }

    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64> {
        let count = sqlx::query_scalar::<_, T::Count>(
            "SELECT COUNT(*) FROM pairings WHERE client_id IS NULL AND expired > $1",
        )
        .bind(now)
        .fetch_one(self.pool())
        .await
        .context("failed to count unconsumed pairings")?;
        Ok(count.into())
    }

    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM pairings WHERE expired < $1")
            .bind(now)
            .execute(self.pool())
            .await
            .context("failed to delete expired pairings")?;
        Ok(T::rows_affected(&result))
    }
}

#[derive(sqlx::FromRow)]
struct PairingSqlRow {
    pairing_id: String,
    expired: String,
    client_id: Option<String>,
}

impl From<PairingSqlRow> for PairingRow {
    fn from(row: PairingSqlRow) -> Self {
        Self {
            pairing_id: row.pairing_id,
            expired: row.expired,
            client_id: row.client_id,
        }
    }
}
