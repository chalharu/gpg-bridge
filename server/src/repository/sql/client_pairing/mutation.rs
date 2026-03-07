use anyhow::Context;
use async_trait::async_trait;

use super::CommonClientPairingMutationRepository;

#[async_trait]
impl CommonClientPairingMutationRepository for crate::repository::PostgresRepository {
    async fn create_client_pairing_common(
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
        .execute(&self.pool)
        .await
        .context("failed to create client pairing")?;
        Ok(())
    }

    async fn delete_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let result =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to delete client pairing")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_jwt_issued_at_common(
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
        .execute(&self.pool)
        .await
        .context("failed to update client pairing jwt issued_at")?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl CommonClientPairingMutationRepository for crate::repository::SqliteRepository {
    async fn create_client_pairing_common(
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
        .execute(&self.pool)
        .await
        .context("failed to create client pairing")?;
        Ok(())
    }

    async fn delete_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let result =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to delete client pairing")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_jwt_issued_at_common(
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
        .execute(&self.pool)
        .await
        .context("failed to update client_jwt_issued_at")?;
        Ok(result.rows_affected() > 0)
    }
}
