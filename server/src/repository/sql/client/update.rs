use anyhow::Context;

use super::CommonClientUpdateRepository;

impl_for_sql_backends!(CommonClientUpdateRepository {
    async fn update_client_device_token_common(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        execute_query!(
            "UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3",
            &self.pool,
            "failed to update client device_token",
            device_token,
            updated_at,
            client_id,
        )?;
        Ok(())
    }

    async fn update_client_default_kid_common(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        execute_query!(
            "UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3",
            &self.pool,
            "failed to update client default_kid",
            default_kid,
            updated_at,
            client_id,
        )?;
        Ok(())
    }

    async fn update_device_jwt_issued_at_common(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        execute_query!(
            "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
            &self.pool,
            "failed to update device_jwt_issued_at",
            issued_at,
            updated_at,
            client_id,
        )?;
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
        let result = execute_query!(
            "UPDATE clients SET public_keys = $1, default_kid = $2, updated_at = $3 WHERE client_id = $4 AND updated_at = $5",
            &self.pool,
            "failed to update client public_keys",
            public_keys,
            default_kid,
            updated_at,
            client_id,
            expected_updated_at,
        )?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_gpg_keys_common(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = execute_query!(
            "UPDATE clients SET gpg_keys = $1, updated_at = $2 WHERE client_id = $3 AND updated_at = $4",
            &self.pool,
            "failed to update client gpg_keys",
            gpg_keys,
            updated_at,
            client_id,
            expected_updated_at,
        )?;
        Ok(result.rows_affected() > 0)
    }
});
