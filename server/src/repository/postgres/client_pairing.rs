use anyhow::Context;

use super::PostgresRepository;
use crate::repository::ClientPairingRow;
use crate::repository::client_pairing::impl_client_pairing_repository;

#[derive(sqlx::FromRow)]
struct PgClientPairingRow {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<PgClientPairingRow> for ClientPairingRow {
    fn from(r: PgClientPairingRow) -> Self {
        Self {
            client_id: r.client_id,
            pairing_id: r.pairing_id,
            client_jwt_issued_at: r.client_jwt_issued_at,
        }
    }
}

impl_client_pairing_repository!(PostgresRepository, PgClientPairingRow, i64, |count: i64| {
    count
});
