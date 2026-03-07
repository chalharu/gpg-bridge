use anyhow::Context;

use super::{ClientRecord, CommonClientLookupRepository};
use crate::repository::ClientRow;

impl_for_sql_backends!(CommonClientLookupRepository {
    async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        let row = fetch_optional_as!(
            ClientRecord,
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
            &self.pool,
            "failed to get client by id",
            client_id,
        )?;
        Ok(row.map(Into::into))
    }

    async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool> {
        let count = fetch_one_scalar!(
            i64,
            "SELECT COUNT(*) FROM clients WHERE client_id = $1",
            &self.pool,
            "failed to check client existence",
            client_id,
        )?;
        Ok(count > 0)
    }

    async fn client_by_device_token_common(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        let row = fetch_optional_as!(
            ClientRecord,
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
            &self.pool,
            "failed to get client by device_token",
            device_token,
        )?;
        Ok(row.map(Into::into))
    }
});
