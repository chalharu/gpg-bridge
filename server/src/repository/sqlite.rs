use anyhow::Context;
use async_trait::async_trait;
use sqlx::SqlitePool;

use super::{MIGRATOR, SignatureRepository, SigningKeyRow};

#[derive(Debug, Clone)]
pub struct SqliteRepository {
    pub(crate) pool: SqlitePool,
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
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("sqlite health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
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
        let row = sqlx::query_as::<_, SqliteSigningKeyRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("failed to get active signing key")?;
        Ok(row.map(Into::into))
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SqliteSigningKeyRow>(
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
struct SqliteSigningKeyRow {
    kid: String,
    private_key: String,
    public_key: String,
    created_at: String,
    expires_at: String,
    is_active: bool,
}

impl From<SqliteSigningKeyRow> for SigningKeyRow {
    fn from(r: SqliteSigningKeyRow) -> Self {
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
    use super::SqliteRepository;
    use crate::config::AppConfig;
    use crate::repository::{MIGRATOR, SignatureRepository, SigningKeyRow, build_repository};
    use sqlx::SqlitePool;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

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
            signing_key_secret: "test-secret-key!".to_owned(),
        }
    }

    /// Build an in-memory SQLite pool with the same connect options used in
    /// production (`foreign_keys(true)`, WAL journal mode).  This lets tests
    /// exercise the real connection settings without needing to downcast
    /// through `Arc<dyn SignatureRepository>`.
    async fn build_sqlite_test_pool() -> SqlitePool {
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
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();

        // Positive case: insert a valid client, then a client_pairings row referencing it.
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ('client-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', '[]', 'kid-1', '[]')",
        )
        .execute(&pool)
        .await
        .expect("inserting a valid client should succeed");

        sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .expect("inserting a client_pairings row with valid FK should succeed");

        // Negative case: inserting a client_pairings row referencing a non-existent client
        // must fail because of the foreign key constraint on client_id.
        let result = sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('nonexistent', 'pair-2', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await;

        let err = result
            .expect_err("foreign key constraint should reject insert with non-existent client_id");
        let msg = err.to_string();
        assert!(
            msg.contains("FOREIGN KEY constraint failed"),
            "expected FK violation error, got: {msg}",
        );
    }

    // ---- signing_keys repository tests ----

    fn make_signing_key_row(kid: &str, is_active: bool, expires_at: &str) -> SigningKeyRow {
        SigningKeyRow {
            kid: kid.to_owned(),
            private_key: "encrypted-private".to_owned(),
            public_key: "{\"kty\":\"EC\"}".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            expires_at: expires_at.to_owned(),
            is_active,
        }
    }

    #[tokio::test]
    async fn store_and_get_active_signing_key() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-1", true, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let active = repo.get_active_signing_key().await.unwrap().unwrap();
        assert_eq!(active.kid, "kid-1");
        assert!(active.is_active);
    }

    #[tokio::test]
    async fn get_signing_key_by_kid() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-2", false, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let found = repo.get_signing_key_by_kid("kid-2").await.unwrap().unwrap();
        assert_eq!(found.kid, "kid-2");
        assert!(!found.is_active);

        let missing = repo.get_signing_key_by_kid("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn retire_signing_key_sets_inactive() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-3", true, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let updated = repo.retire_signing_key("kid-3").await.unwrap();
        assert!(updated);

        let retired = repo.get_signing_key_by_kid("kid-3").await.unwrap().unwrap();
        assert!(!retired.is_active);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn retire_nonexistent_signing_key_returns_false() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let updated = repo.retire_signing_key("nonexistent").await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn delete_expired_signing_keys_removes_old() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let expired = make_signing_key_row("kid-old", false, "2025-01-01T00:00:00Z");
        let valid = make_signing_key_row("kid-new", false, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&expired).await.unwrap();
        repo.store_signing_key(&valid).await.unwrap();

        let deleted = repo
            .delete_expired_signing_keys("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        assert!(
            repo.get_signing_key_by_kid("kid-old")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_signing_key_by_kid("kid-new")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn no_active_key_returns_none() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(repo.get_active_signing_key().await.unwrap().is_none());
    }
}
