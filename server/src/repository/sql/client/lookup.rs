use anyhow::Context;
use async_trait::async_trait;

use super::{ClientRecord, CommonClientLookupRepository};
use crate::repository::ClientRow;

#[async_trait]
impl CommonClientLookupRepository for crate::repository::PostgresRepository {
    async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, ClientRecord>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by id")?;
        Ok(row.map(Into::into))
    }

    async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(&self.pool)
                .await
                .context("failed to check client existence")?;
        Ok(count > 0)
    }

    async fn client_by_device_token_common(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, ClientRecord>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
        )
        .bind(device_token)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by device_token")?;
        Ok(row.map(Into::into))
    }
}

#[async_trait]
impl CommonClientLookupRepository for crate::repository::SqliteRepository {
    async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, ClientRecord>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by id")?;
        Ok(row.map(Into::into))
    }

    async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(&self.pool)
                .await
                .context("failed to check client existence")?;
        Ok(count > 0)
    }

    async fn client_by_device_token_common(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, ClientRecord>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
        )
        .bind(device_token)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by device_token")?;
        Ok(row.map(Into::into))
    }
}
