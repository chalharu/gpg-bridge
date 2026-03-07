use sqlx::PgPool;

use crate::repository::sql::DbRepository;

mod request;

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
}

impl DbRepository for PostgresRepository {
    type Database = sqlx::Postgres;
    type Count = i64;

    fn pool(&self) -> &sqlx::Pool<Self::Database> {
        &self.pool
    }

    fn database_backend_name(&self) -> &'static str {
        "postgres"
    }

    fn rows_affected(result: &<Self::Database as sqlx::Database>::QueryResult) -> u64 {
        result.rows_affected()
    }
}
