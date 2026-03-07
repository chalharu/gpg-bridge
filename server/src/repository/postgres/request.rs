use anyhow::Context;

use super::PostgresRepository;
use crate::repository::request::impl_request_repository;
use crate::repository::{FullRequestRow, RequestRow};

#[derive(sqlx::FromRow)]
struct PgRequestRow {
    request_id: String,
    status: String,
    daemon_public_key: String,
}

impl From<PgRequestRow> for RequestRow {
    fn from(r: PgRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            daemon_public_key: r.daemon_public_key,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PgFullRequestRow {
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

impl From<PgFullRequestRow> for FullRequestRow {
    fn from(r: PgFullRequestRow) -> Self {
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

const PG_COUNT_PENDING_REQUESTS_FOR_PAIRING_SQL: &str = "SELECT COUNT(*) FROM requests WHERE status IN ('created', 'pending') AND client_ids::jsonb ? $1 AND pairing_ids::jsonb ->> $1 = $2";
const PG_PENDING_REQUESTS_FOR_CLIENT_SQL: &str = "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE status = 'pending' AND expired > NOW() AND client_ids::jsonb ? $1 AND NOT (unavailable_client_ids::jsonb ? $1)";
const PG_SELECT_UNAVAILABLE_FOR_UPDATE_SQL: &str = "SELECT unavailable_client_ids, client_ids, status FROM requests WHERE request_id = $1 FOR UPDATE";
const PG_IS_KID_IN_FLIGHT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM requests CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e2e_kids::jsonb) = 'array' THEN e2e_kids::jsonb ELSE '[]'::jsonb END) AS elem WHERE requests.status IN ('created', 'pending') AND elem = $1)";

impl_request_repository!(
    PostgresRepository,
    PgRequestRow,
    PgFullRequestRow,
    i64,
    |count: i64| count,
    PG_COUNT_PENDING_REQUESTS_FOR_PAIRING_SQL,
    PG_PENDING_REQUESTS_FOR_CLIENT_SQL,
    PG_SELECT_UNAVAILABLE_FOR_UPDATE_SQL,
    bool,
    |found: bool| found,
    PG_IS_KID_IN_FLIGHT_SQL
);
