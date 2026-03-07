use anyhow::Context;
use async_trait::async_trait;
use sqlx::{ColumnIndex, Database, Decode, Encode, Executor, FromRow, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::{ClientPairingRepository, ClientPairingRow};

#[async_trait]
impl<T, DB> ClientPairingRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'c> &'c mut DB::Connection: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
    for<'r> ClientPairingSqlRow: FromRow<'r, DB::Row>,
    for<'r> T::Count: Decode<'r, DB> + Type<DB>,
    usize: ColumnIndex<DB::Row>,
{
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, ClientPairingSqlRow>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(self.pool())
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ($1, $2, $3)",
        )
        .bind(client_id)
        .bind(pairing_id)
        .bind(client_jwt_issued_at)
        .execute(self.pool())
        .await
        .context("failed to create client pairing")?;
        Ok(())
    }

    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let result =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(self.pool())
                .await
                .context("failed to delete client pairing")?;
        Ok(T::rows_affected(&result) > 0)
    }

    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .context("failed to begin transaction")?;

        let del =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = T::rows_affected(&del) > 0;

        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, T::Count>(
                "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
            )
            .bind(client_id)
            .fetch_one(&mut *tx)
            .await
            .context("failed to count remaining pairings")?;

            if remaining.into() == 0 {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete client")?;
                client_deleted = true;
            }
        }

        tx.commit().await.context("failed to commit transaction")?;
        Ok((pairing_deleted, client_deleted))
    }

    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE client_pairings SET client_jwt_issued_at = $1 WHERE client_id = $2 AND pairing_id = $3",
        )
        .bind(issued_at)
        .bind(client_id)
        .bind(pairing_id)
        .execute(self.pool())
        .await
        .context("failed to update client_jwt_issued_at")?;
        Ok(T::rows_affected(&result) > 0)
    }
}

#[derive(sqlx::FromRow)]
struct ClientPairingSqlRow {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<ClientPairingSqlRow> for ClientPairingRow {
    fn from(row: ClientPairingSqlRow) -> Self {
        Self {
            client_id: row.client_id,
            pairing_id: row.pairing_id,
            client_jwt_issued_at: row.client_jwt_issued_at,
        }
    }
}
