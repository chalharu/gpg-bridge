use anyhow::Context;
use async_trait::async_trait;

use super::CommonClientUpdateRepository;

#[async_trait]
impl CommonClientUpdateRepository for crate::repository::PostgresRepository {
    async fn update_client_device_token_common(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3")
            .bind(device_token)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client device_token")?;
        Ok(())
    }

    async fn update_client_default_kid_common(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3")
            .bind(default_kid)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client default_kid")?;
        Ok(())
    }

    async fn update_device_jwt_issued_at_common(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
        )
        .bind(issued_at)
        .bind(updated_at)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .context("failed to update device_jwt_issued_at")?;
        Ok(())
    }

    async fn update_client_public_keys_common(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET public_keys = $1, default_kid = $2, updated_at = $3 WHERE client_id = $4 AND updated_at = $5",
        )
        .bind(public_keys)
        .bind(default_kid)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client public_keys")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_gpg_keys_common(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET gpg_keys = $1, updated_at = $2 WHERE client_id = $3 AND updated_at = $4",
        )
        .bind(gpg_keys)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client gpg_keys")?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl CommonClientUpdateRepository for crate::repository::SqliteRepository {
    async fn update_client_device_token_common(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3")
            .bind(device_token)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client device_token")?;
        Ok(())
    }

    async fn update_client_default_kid_common(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3")
            .bind(default_kid)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client default_kid")?;
        Ok(())
    }

    async fn update_device_jwt_issued_at_common(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
        )
        .bind(issued_at)
        .bind(updated_at)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .context("failed to update device_jwt_issued_at")?;
        Ok(())
    }

    async fn update_client_public_keys_common(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET public_keys = $1, default_kid = $2, updated_at = $3 WHERE client_id = $4 AND updated_at = $5",
        )
        .bind(public_keys)
        .bind(default_kid)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client public_keys")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_gpg_keys_common(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET gpg_keys = $1, updated_at = $2 WHERE client_id = $3 AND updated_at = $4",
        )
        .bind(gpg_keys)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client gpg_keys")?;
        Ok(result.rows_affected() > 0)
    }
}
