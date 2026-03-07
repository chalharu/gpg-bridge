use anyhow::Context;

use super::CommonClientLifecycleRepository;
use crate::repository::ClientRow;

impl_for_sql_backends!(CommonClientLifecycleRepository {
    async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()> {
        execute_query!(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &self.pool,
            "failed to create client",
            &row.client_id,
            &row.created_at,
            &row.updated_at,
            &row.device_token,
            &row.device_jwt_issued_at,
            &row.public_keys,
            &row.default_kid,
            &row.gpg_keys,
        )?;
        Ok(())
    }

    async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()> {
        execute_query!(
            "DELETE FROM clients WHERE client_id = $1",
            &self.pool,
            "failed to delete client",
            client_id,
        )?;
        Ok(())
    }
});
