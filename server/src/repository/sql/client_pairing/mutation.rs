use anyhow::Context;

use super::CommonClientPairingMutationRepository;

impl_for_sql_backends!(CommonClientPairingMutationRepository {
    async fn create_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        execute_query!(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ($1, $2, $3)",
            &self.pool,
            "failed to create client pairing",
            client_id,
            pairing_id,
            client_jwt_issued_at,
        )?;
        Ok(())
    }

    async fn delete_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let result = execute_query!(
            "DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2",
            &self.pool,
            "failed to delete client pairing",
            client_id,
            pairing_id,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_jwt_issued_at_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        let result = execute_query!(
            "UPDATE client_pairings SET client_jwt_issued_at = $1 WHERE client_id = $2 AND pairing_id = $3",
            &self.pool,
            "failed to update client pairing jwt issued_at",
            issued_at,
            client_id,
            pairing_id,
        )?;
        Ok(result.rows_affected() > 0)
    }
});
