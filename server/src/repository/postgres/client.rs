use anyhow::Context;

use super::PostgresRepository;
use crate::repository::ClientRow;
use crate::repository::client::impl_client_repository;

#[derive(sqlx::FromRow)]
struct PgClientRow {
    client_id: String,
    created_at: String,
    updated_at: String,
    device_token: String,
    device_jwt_issued_at: String,
    public_keys: String,
    default_kid: String,
    gpg_keys: String,
}

impl From<PgClientRow> for ClientRow {
    fn from(r: PgClientRow) -> Self {
        Self {
            client_id: r.client_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            device_token: r.device_token,
            device_jwt_issued_at: r.device_jwt_issued_at,
            public_keys: r.public_keys,
            default_kid: r.default_kid,
            gpg_keys: r.gpg_keys,
        }
    }
}

impl_client_repository!(PostgresRepository, PgClientRow, i64, |count: i64| count);
