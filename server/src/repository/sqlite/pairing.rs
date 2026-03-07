use anyhow::Context;

use super::SqliteRepository;
use crate::repository::PairingRow;
use crate::repository::pairing::impl_pairing_repository;

#[derive(sqlx::FromRow)]
struct SqlitePairingRow {
    pairing_id: String,
    expired: String,
    client_id: Option<String>,
}

impl From<SqlitePairingRow> for PairingRow {
    fn from(r: SqlitePairingRow) -> Self {
        Self {
            pairing_id: r.pairing_id,
            expired: r.expired,
            client_id: r.client_id,
        }
    }
}

impl_pairing_repository!(SqliteRepository, SqlitePairingRow, i32, i64::from);
