use anyhow::Context;
use async_trait::async_trait;

use super::PairingRecord;
use crate::repository::{PairingRepository, PairingRow};

#[async_trait]
trait CommonPairingRepository: Send + Sync {
    async fn create_pairing_common(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()>;
    async fn get_pairing_by_id_common(
        &self,
        pairing_id: &str,
    ) -> anyhow::Result<Option<PairingRow>>;
    async fn consume_pairing_common(
        &self,
        pairing_id: &str,
        client_id: &str,
    ) -> anyhow::Result<bool>;
    async fn count_unconsumed_pairings_common(&self, now: &str) -> anyhow::Result<i64>;
    async fn delete_expired_pairings_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> PairingRepository for T
where
    T: CommonPairingRepository + Send + Sync,
{
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        self.create_pairing_common(pairing_id, expired).await
    }

    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        self.get_pairing_by_id_common(pairing_id).await
    }

    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        self.consume_pairing_common(pairing_id, client_id).await
    }

    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64> {
        self.count_unconsumed_pairings_common(now).await
    }

    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_pairings_common(now).await
    }
}

impl From<PairingRecord> for PairingRow {
    fn from(record: PairingRecord) -> Self {
        Self {
            pairing_id: record.pairing_id,
            expired: record.expired,
            client_id: record.client_id,
        }
    }
}

impl_for_sql_backends!(CommonPairingRepository {
    async fn create_pairing_common(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        execute_query!(
            "INSERT INTO pairings (pairing_id, expired) VALUES ($1, $2)",
            &self.pool,
            "failed to create pairing",
            pairing_id,
            expired,
        )?;
        Ok(())
    }

    async fn get_pairing_by_id_common(
        &self,
        pairing_id: &str,
    ) -> anyhow::Result<Option<PairingRow>> {
        let row = fetch_optional_as!(
            PairingRecord,
            "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
            &self.pool,
            "failed to get pairing by id",
            pairing_id,
        )?;
        Ok(row.map(Into::into))
    }

    async fn consume_pairing_common(
        &self,
        pairing_id: &str,
        client_id: &str,
    ) -> anyhow::Result<bool> {
        let result = execute_query!(
            "UPDATE pairings SET client_id = $1 WHERE pairing_id = $2 AND client_id IS NULL",
            &self.pool,
            "failed to consume pairing",
            client_id,
            pairing_id,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_unconsumed_pairings_common(&self, now: &str) -> anyhow::Result<i64> {
        let count = fetch_one_scalar!(
            i64,
            "SELECT COUNT(*) FROM pairings WHERE client_id IS NULL AND expired > $1",
            &self.pool,
            "failed to count unconsumed pairings",
            now,
        )?;
        Ok(count)
    }

    async fn delete_expired_pairings_common(&self, now: &str) -> anyhow::Result<u64> {
        let result = execute_query!(
            "DELETE FROM pairings WHERE expired < $1",
            &self.pool,
            "failed to delete expired pairings",
            now,
        )?;
        Ok(result.rows_affected())
    }
});
