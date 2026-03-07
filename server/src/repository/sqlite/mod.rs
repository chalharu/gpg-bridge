use sqlx::SqlitePool;

use crate::repository::sql::DbRepository;

mod request;

#[derive(Debug, Clone)]
pub struct SqliteRepository {
    pub(crate) pool: SqlitePool,
}

impl DbRepository for SqliteRepository {
    type Database = sqlx::Sqlite;
    type Count = i32;

    fn pool(&self) -> &sqlx::Pool<Self::Database> {
        &self.pool
    }

    fn database_backend_name(&self) -> &'static str {
        "sqlite"
    }

    fn rows_affected(result: &<Self::Database as sqlx::Database>::QueryResult) -> u64 {
        result.rows_affected()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sqlx::SqlitePool;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    /// Build an in-memory SQLite pool with the same connect options used in
    /// production (`foreign_keys(true)`, WAL journal mode).
    pub(crate) async fn build_sqlite_test_pool() -> SqlitePool {
        let options = "sqlite::memory:"
            .parse::<SqliteConnectOptions>()
            .unwrap()
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);

        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap()
    }
}
