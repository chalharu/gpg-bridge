use anyhow::Context;
use async_trait::async_trait;

use super::{ClientPairingRecord, CommonClientPairingQueryRepository};
use crate::repository::ClientPairingRow;

#[async_trait]
impl CommonClientPairingQueryRepository for crate::repository::PostgresRepository {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, ClientPairingRecord>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

#[async_trait]
impl CommonClientPairingQueryRepository for crate::repository::SqliteRepository {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, ClientPairingRecord>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
