use anyhow::Context;

use super::{ClientPairingRecord, CommonClientPairingQueryRepository};
use crate::repository::ClientPairingRow;

impl_for_sql_backends!(CommonClientPairingQueryRepository {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = fetch_all_as!(
            ClientPairingRecord,
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
            &self.pool,
            "failed to get client pairings",
            client_id,
        )?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
});
