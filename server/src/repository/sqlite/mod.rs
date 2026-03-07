mod infrastructure;
mod request;

pub type SqliteRepository = super::sql::SqlRepository<sqlx::Sqlite>;

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
