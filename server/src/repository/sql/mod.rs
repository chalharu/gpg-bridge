mod audit_log;
mod cleanup;
mod client;
mod client_pairing;
mod infrastructure;
mod jti;
mod pairing;
mod signing_key;

use sqlx::{Database, Pool};

pub(crate) trait DbRepository: Send + Sync {
    type Database: Database;
    type Count: Send + Unpin + Into<i64>;

    fn pool(&self) -> &Pool<Self::Database>;
    fn database_backend_name(&self) -> &'static str;
    fn rows_affected(result: &<Self::Database as Database>::QueryResult) -> u64;
}
