mod infrastructure;
mod request;
pub type PostgresRepository = super::sql::SqlRepository<sqlx::Postgres>;
