use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;

use super::{
    AuditLogRow, ClientPairingRow, ClientRow, CreateRequestRow, FullRequestRow, MIGRATOR,
    PairingRow, RequestRow, SignatureRepository, SigningKeyRow,
};

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pub(crate) pool: PgPool,
}

impl_signature_repository!(
    PostgresRepository,
    backend = "postgres",
    count_scalar = i64,
    count_pending_for_pairing_sql = "SELECT COUNT(*) FROM requests WHERE status IN ('created', 'pending') AND client_ids::jsonb ? $1 AND pairing_ids::jsonb ->> $1 = $2",
    get_pending_for_client_sql = "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE status = 'pending' AND expired > NOW() AND client_ids::jsonb ? $1 AND NOT (unavailable_client_ids::jsonb ? $1)",
    add_unavail_select_sql = "SELECT unavailable_client_ids, client_ids, status FROM requests WHERE request_id = $1 FOR UPDATE",
    is_kid_in_flight_sql = "SELECT EXISTS(SELECT 1 FROM requests CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e2e_kids::jsonb) = 'array' THEN e2e_kids::jsonb ELSE '[]'::jsonb END) AS elem WHERE requests.status IN ('created', 'pending') AND elem = $1)",
    is_kid_in_flight_scalar = bool,
);

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
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            fcm_service_account_key_path: None,
            fcm_project_id: None,
            cleanup_interval_seconds: 60,
            unpaired_client_max_age_hours: 24,
            audit_log_approved_retention_seconds: 31_536_000,
            audit_log_denied_retention_seconds: 15_768_000,
            audit_log_conflict_retention_seconds: 7_884_000,
        };

        let repository = build_repository(&config).await.unwrap();
        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "postgres");

        postgresql.stop().await.unwrap();
    }
}
