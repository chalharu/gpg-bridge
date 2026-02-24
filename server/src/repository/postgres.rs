use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;

use super::{MIGRATOR, SignatureRepository, SigningKeyRow};

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
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
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("postgres health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, private_key, public_key, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&key.kid)
        .bind(&key.private_key)
        .bind(&key.public_key)
        .bind(&key.created_at)
        .bind(&key.expires_at)
        .bind(key.is_active)
        .execute(&self.pool)
        .await
        .context("failed to store signing key")?;
        Ok(())
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, PgSigningKeyRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("failed to get active signing key")?;
        Ok(row.map(Into::into))
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, PgSigningKeyRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get signing key by kid")?;
        Ok(row.map(Into::into))
    }

    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE signing_keys SET is_active = FALSE WHERE kid = $1")
            .bind(kid)
            .execute(&self.pool)
            .await
            .context("failed to retire signing key")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM signing_keys WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired signing keys")?;
        Ok(result.rows_affected())
    }
}

#[derive(sqlx::FromRow)]
struct PgSigningKeyRow {
    kid: String,
    private_key: String,
    public_key: String,
    created_at: String,
    expires_at: String,
    is_active: bool,
}

impl From<PgSigningKeyRow> for SigningKeyRow {
    fn from(r: PgSigningKeyRow) -> Self {
        Self {
            kid: r.kid,
            private_key: r.private_key,
            public_key: r.public_key,
            created_at: r.created_at,
            expires_at: r.expires_at,
            is_active: r.is_active,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::AppConfig;
    use crate::repository::build_repository;
    use postgresql_embedded::PostgreSQL;
    use sqlx::{ConnectOptions, postgres::PgConnectOptions};

    #[tokio::test]
    #[ignore = "requires downloading/starting embedded PostgreSQL"]
    async fn postgres_repository_connects_to_embedded_postgresql() {
        let mut postgresql = PostgreSQL::default();
        if let Err(e) = postgresql.setup().await {
            eprintln!("Skipping test: PostgreSQL setup failed (e.g. rate limit): {e}");
            return;
        }
        if let Err(e) = postgresql.start().await {
            eprintln!("Skipping test: PostgreSQL start failed: {e}");
            postgresql.stop().await.ok();
            return;
        }

        let database_name = "gpg_bridge_test";
        if let Err(e) = postgresql.create_database(database_name).await {
            eprintln!("Skipping test: create_database failed: {e}");
            postgresql.stop().await.ok();
            return;
        }

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
            signing_key_secret: "test-secret-key!".to_owned(),
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "postgres");

        postgresql.stop().await.unwrap();
    }
}
