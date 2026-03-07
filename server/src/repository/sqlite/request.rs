use anyhow::Context;

use super::SqliteRepository;
use crate::repository::request::impl_request_repository;
use crate::repository::{FullRequestRow, RequestRow};

#[derive(sqlx::FromRow)]
struct SqliteRequestRow {
    request_id: String,
    status: String,
    daemon_public_key: String,
}

impl From<SqliteRequestRow> for RequestRow {
    fn from(r: SqliteRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            daemon_public_key: r.daemon_public_key,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteFullRequestRow {
    request_id: String,
    status: String,
    expired: String,
    signature: Option<String>,
    client_ids: String,
    daemon_public_key: String,
    daemon_enc_public_key: String,
    pairing_ids: String,
    e2e_kids: String,
    encrypted_payloads: Option<String>,
    unavailable_client_ids: String,
}

impl From<SqliteFullRequestRow> for FullRequestRow {
    fn from(r: SqliteFullRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            expired: r.expired,
            signature: r.signature,
            client_ids: r.client_ids,
            daemon_public_key: r.daemon_public_key,
            daemon_enc_public_key: r.daemon_enc_public_key,
            pairing_ids: r.pairing_ids,
            e2e_kids: r.e2e_kids,
            encrypted_payloads: r.encrypted_payloads,
            unavailable_client_ids: r.unavailable_client_ids,
        }
    }
}

const SQLITE_COUNT_PENDING_REQUESTS_FOR_PAIRING_SQL: &str = "SELECT COUNT(*) FROM requests WHERE status IN ('created', 'pending') AND EXISTS (SELECT 1 FROM json_each(requests.client_ids) WHERE json_each.value = $1) AND json_extract(requests.pairing_ids, '$.\"' || $1 || '\"') = $2";
const SQLITE_PENDING_REQUESTS_FOR_CLIENT_SQL: &str = "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE status = 'pending' AND expired > datetime('now') AND EXISTS (SELECT 1 FROM json_each(requests.client_ids) WHERE json_each.value = $1) AND NOT EXISTS (SELECT 1 FROM json_each(requests.unavailable_client_ids) WHERE json_each.value = $1)";
const SQLITE_SELECT_UNAVAILABLE_SQL: &str =
    "SELECT unavailable_client_ids, client_ids, status FROM requests WHERE request_id = $1";
const SQLITE_IS_KID_IN_FLIGHT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM requests, json_each(requests.e2e_kids) AS je WHERE requests.status IN ('created', 'pending') AND je.value = $1)";

impl_request_repository!(
    SqliteRepository,
    SqliteRequestRow,
    SqliteFullRequestRow,
    i32,
    i64::from,
    SQLITE_COUNT_PENDING_REQUESTS_FOR_PAIRING_SQL,
    SQLITE_PENDING_REQUESTS_FOR_CLIENT_SQL,
    SQLITE_SELECT_UNAVAILABLE_SQL,
    i32,
    |found: i32| found != 0,
    SQLITE_IS_KID_IN_FLIGHT_SQL
);
