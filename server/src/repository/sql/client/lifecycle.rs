use anyhow::Context;
use async_trait::async_trait;

use super::CommonClientLifecycleRepository;
use crate::repository::ClientRow;

#[async_trait]
impl CommonClientLifecycleRepository for crate::repository::PostgresRepository {
    async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&row.client_id)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .bind(&row.device_token)
        .bind(&row.device_jwt_issued_at)
        .bind(&row.public_keys)
        .bind(&row.default_kid)
        .bind(&row.gpg_keys)
        .execute(&self.pool)
        .await
        .context("failed to create client")?;
        Ok(())
    }

    async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to delete client")?;
        Ok(())
    }
}

#[async_trait]
impl CommonClientLifecycleRepository for crate::repository::SqliteRepository {
    async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&row.client_id)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .bind(&row.device_token)
        .bind(&row.device_jwt_issued_at)
        .bind(&row.public_keys)
        .bind(&row.default_kid)
        .bind(&row.gpg_keys)
        .execute(&self.pool)
        .await
        .context("failed to create client")?;
        Ok(())
    }

    async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to delete client")?;
        Ok(())
    }
}
