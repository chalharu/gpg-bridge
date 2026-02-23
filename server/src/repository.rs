use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use sqlx::{
    PgPool, SqlitePool,
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::config::{AppConfig, DatabaseKind, detect_database_kind};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[async_trait]
pub trait SignatureRepository: Send + Sync + std::fmt::Debug {
    async fn run_migrations(&self) -> anyhow::Result<()>;
    async fn health_check(&self) -> anyhow::Result<()>;
    fn backend_name(&self) -> &'static str;
    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

#[async_trait]
impl SignatureRepository for PostgresRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run postgres migrations")
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("postgres health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
pub struct SqliteRepository {
    pool: SqlitePool,
}

#[async_trait]
impl SignatureRepository for SqliteRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run sqlite migrations")
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("sqlite health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub async fn build_repository(config: &AppConfig) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let kind = detect_database_kind(&config.database_url)?;

    match kind {
        DatabaseKind::Postgres => {
            let pool = PgPoolOptions::new()
                .max_connections(config.db_max_connections)
                .min_connections(config.db_min_connections)
                .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
                .connect(&config.database_url)
                .await
                .context("failed to connect postgres pool")?;

            Ok(Arc::new(PostgresRepository { pool }))
        }
        DatabaseKind::Sqlite => {
            let options = config
                .database_url
                .parse::<SqliteConnectOptions>()
                .context("failed to parse sqlite connection options")?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true);

            let pool = SqlitePoolOptions::new()
                .max_connections(config.db_max_connections)
                .min_connections(config.db_min_connections)
                .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
                .connect_with(options)
                .await
                .context("failed to connect sqlite pool")?;

            Ok(Arc::new(SqliteRepository { pool }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postgresql_embedded::PostgreSQL;
    use sqlx::{ConnectOptions, postgres::PgConnectOptions};

    fn sqlite_test_config() -> AppConfig {
        AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "sqlite::memory:".to_owned(),
            db_max_connections: 4,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "plain".to_owned(),
        }
    }

    #[tokio::test]
    async fn sqlite_repository_runs_migration_and_health_check() {
        let config = sqlite_test_config();
        let repository = build_repository(&config).await.unwrap();

        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "sqlite");
    }

    #[tokio::test]
    async fn sqlite_enforces_foreign_key_constraints() {
        let config = sqlite_test_config();
        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();

        // Downcast to SqliteRepository to access the pool
        let sqlite_repo = repository
            .as_any()
            .downcast_ref::<SqliteRepository>()
            .expect("expected SqliteRepository");

        // Inserting a client_pairings row referencing a non-existent client
        // must fail because of the foreign key constraint on client_id.
        let result = sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('nonexistent', 'pair-1', '2026-01-01T00:00:00Z')",
        )
        .execute(&sqlite_repo.pool)
        .await;

        assert!(
            result.is_err(),
            "foreign key constraint should reject insert with non-existent client_id"
        );
    }

    #[tokio::test]
    #[ignore = "requires downloading/starting embedded PostgreSQL"]
    async fn postgres_repository_connects_to_embedded_postgresql() {
        let mut postgresql = PostgreSQL::default();
        postgresql.setup().await.unwrap();
        postgresql.start().await.unwrap();

        let database_name = "gpg_bridge_test";
        postgresql.create_database(database_name).await.unwrap();

        let settings = postgresql.settings();
        let database_url = PgConnectOptions::new()
            .host(&settings.host)
            .port(settings.port)
            .username(&settings.username)
            .password(&settings.password)
            .database(database_name)
            .to_url_lossy()
            .to_string();

        let config = AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url,
            db_max_connections: 4,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "plain".to_owned(),
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "postgres");

        postgresql.stop().await.unwrap();
    }
}
