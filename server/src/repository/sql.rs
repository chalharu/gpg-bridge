use sqlx::{Database, FromRow, Pool};

macro_rules! execute_query {
    ($sql:expr, $executor:expr, $context:literal $(, $param:expr )* $(,)?) => {{
        let query = sqlx::query($sql);
        $(let query = query.bind($param);)*
        query
            .execute($executor)
            .await
            .context($context)
    }};
}

macro_rules! fetch_optional_as {
    ($record:ty, $sql:expr, $executor:expr, $context:literal $(, $param:expr )* $(,)?) => {{
        let query = sqlx::query_as::<_, $record>($sql);
        $(let query = query.bind($param);)*
        query
            .fetch_optional($executor)
            .await
            .context($context)
    }};
}

macro_rules! fetch_all_as {
    ($record:ty, $sql:expr, $executor:expr, $context:literal $(, $param:expr )* $(,)?) => {{
        let query = sqlx::query_as::<_, $record>($sql);
        $(let query = query.bind($param);)*
        query
            .fetch_all($executor)
            .await
            .context($context)
    }};
}

macro_rules! fetch_one_scalar {
    ($record:ty, $sql:expr, $executor:expr, $context:literal $(, $param:expr )* $(,)?) => {{
        let query = sqlx::query_scalar::<_, $record>($sql);
        $(let query = query.bind($param);)*
        query
            .fetch_one($executor)
            .await
            .context($context)
    }};
}

macro_rules! impl_for_sql_backends {
    ($trait_name:ident { $($item:item)* }) => {
        #[async_trait::async_trait]
        impl $trait_name for crate::repository::PostgresRepository {
            $($item)*
        }

        #[async_trait::async_trait]
        impl $trait_name for crate::repository::SqliteRepository {
            $($item)*
        }
    };
}

mod audit_log;
mod cleanup;
mod client;
mod client_pairing;
mod jti;
mod pairing;
mod signing_key;

trait DbRepository {
    type Database: sqlx::Database;

    fn pool(&self) -> &sqlx::Pool<Self::Database>;
}

impl DbRepository for crate::repository::PostgresRepository {
    type Database = sqlx::Postgres;

    fn pool(&self) -> &sqlx::Pool<Self::Database> {
        &self.pool
    }
}

impl DbRepository for crate::repository::SqliteRepository {
    type Database = sqlx::Sqlite;

    fn pool(&self) -> &sqlx::Pool<Self::Database> {
        &self.pool
    }
}

#[derive(Debug, Clone)]
pub struct SqlRepository<DB: Database> {
    pub(crate) pool: Pool<DB>,
}

#[derive(FromRow)]
pub(super) struct SigningKeyRecord {
    pub(super) kid: String,
    pub(super) private_key: String,
    pub(super) public_key: String,
    pub(super) created_at: String,
    pub(super) expires_at: String,
    pub(super) is_active: bool,
}

#[derive(FromRow)]
pub(super) struct ClientRecord {
    pub(super) client_id: String,
    pub(super) created_at: String,
    pub(super) updated_at: String,
    pub(super) device_token: String,
    pub(super) device_jwt_issued_at: String,
    pub(super) public_keys: String,
    pub(super) default_kid: String,
    pub(super) gpg_keys: String,
}

#[derive(FromRow)]
pub(super) struct PairingRecord {
    pub(super) pairing_id: String,
    pub(super) expired: String,
    pub(super) client_id: Option<String>,
}

#[derive(FromRow)]
pub(super) struct ClientPairingRecord {
    pub(super) client_id: String,
    pub(super) pairing_id: String,
    pub(super) client_jwt_issued_at: String,
}
