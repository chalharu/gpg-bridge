use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;

use super::{
    ClientPairingRow, ClientRow, MIGRATOR, RequestRow, SignatureRepository, SigningKeyRow,
};

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

    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, PgClientRow>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by id")?;
        Ok(row.map(Into::into))
    }

    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&row.client_id)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .bind(&row.device_token)
        .bind(&row.device_jwt_issued_at)
        .bind(&row.public_keys)
        .bind(&row.default_kid)
        .bind(&row.gpg_keys)
        .execute(&self.pool)
        .await
        .context("failed to create client")?;
        Ok(())
    }

    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(&self.pool)
                .await
                .context("failed to check client existence")?;
        Ok(count > 0)
    }

    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, PgClientRow>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
        )
        .bind(device_token)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by device_token")?;
        Ok(row.map(Into::into))
    }

    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3")
            .bind(device_token)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client device_token")?;
        Ok(())
    }

    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3")
            .bind(default_kid)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client default_kid")?;
        Ok(())
    }

    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to delete client")?;
        Ok(())
    }

    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
        )
        .bind(issued_at)
        .bind(updated_at)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .context("failed to update device_jwt_issued_at")?;
        Ok(())
    }

    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, PgClientPairingRow>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>> {
        let row = sqlx::query_as::<_, PgRequestRow>(
            "SELECT request_id, status, daemon_public_key FROM requests WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get request by id")?;
        Ok(row.map(Into::into))
    }

    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expired)
        .execute(&self.pool)
        .await
        .context("failed to store jti")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired jtis")?;
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

#[derive(sqlx::FromRow)]
struct PgClientRow {
    client_id: String,
    created_at: String,
    updated_at: String,
    device_token: String,
    device_jwt_issued_at: String,
    public_keys: String,
    default_kid: String,
    gpg_keys: String,
}

impl From<PgClientRow> for ClientRow {
    fn from(r: PgClientRow) -> Self {
        Self {
            client_id: r.client_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            device_token: r.device_token,
            device_jwt_issued_at: r.device_jwt_issued_at,
            public_keys: r.public_keys,
            default_kid: r.default_kid,
            gpg_keys: r.gpg_keys,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PgClientPairingRow {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<PgClientPairingRow> for ClientPairingRow {
    fn from(r: PgClientPairingRow) -> Self {
        Self {
            client_id: r.client_id,
            pairing_id: r.pairing_id,
            client_jwt_issued_at: r.client_jwt_issued_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PgRequestRow {
    request_id: String,
    status: String,
    daemon_public_key: String,
}

impl From<PgRequestRow> for RequestRow {
    fn from(r: PgRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            daemon_public_key: r.daemon_public_key,
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
            base_url: "http://localhost:3000".to_owned(),
            rate_limit_strict_quota: 10,
            rate_limit_strict_window_seconds: 60,
            rate_limit_standard_quota: 60,
            rate_limit_standard_window_seconds: 60,
            rate_limit_sse_max_per_ip: 20,
            rate_limit_sse_max_per_key: 1,
            device_jwt_validity_seconds: 31_536_000,
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "postgres");

        postgresql.stop().await.unwrap();
    }
}
