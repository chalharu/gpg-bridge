use anyhow::Context;

use super::SqliteRepository;
use crate::repository::ClientPairingRow;
use crate::repository::client_pairing::impl_client_pairing_repository;

#[derive(sqlx::FromRow)]
struct SqliteClientPairingRow {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<SqliteClientPairingRow> for ClientPairingRow {
    fn from(r: SqliteClientPairingRow) -> Self {
        Self {
            client_id: r.client_id,
            pairing_id: r.pairing_id,
            client_jwt_issued_at: r.client_jwt_issued_at,
        }
    }
}

impl_client_pairing_repository!(SqliteRepository, SqliteClientPairingRow, i32, i64::from);
