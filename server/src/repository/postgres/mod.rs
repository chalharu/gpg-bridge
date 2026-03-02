use sqlx::PgPool;

mod audit_log;
mod cleanup;
mod client;
mod client_pairing;
mod infrastructure;
mod jti;
mod pairing;
mod request;
mod signing_key;

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
}
