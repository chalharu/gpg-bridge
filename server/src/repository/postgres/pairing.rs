use anyhow::Context;

use super::PostgresRepository;
use crate::repository::PairingRow;
use crate::repository::pairing::impl_pairing_repository;

#[derive(sqlx::FromRow)]
struct PgPairingRow {
    pairing_id: String,
    expired: String,
    client_id: Option<String>,
}

impl From<PgPairingRow> for PairingRow {
    fn from(r: PgPairingRow) -> Self {
        Self {
            pairing_id: r.pairing_id,
            expired: r.expired,
            client_id: r.client_id,
        }
    }
}

impl_pairing_repository!(PostgresRepository, PgPairingRow, i64, |count: i64| count);
