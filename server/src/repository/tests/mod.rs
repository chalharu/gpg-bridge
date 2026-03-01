use crate::config::AppConfig;
use crate::repository::MIGRATOR;
use crate::repository::sqlite::SqliteRepository;
use crate::repository::sqlite::tests::build_sqlite_test_pool;

mod audit_log_tests;
mod cleanup_tests;
mod client_pairing_tests;
mod client_tests;
mod infrastructure_tests;
mod jti_tests;
mod pairing_tests;
mod request_tests;
mod signing_key_tests;

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
    }
}

async fn build_sqlite_test_repo() -> (SqliteRepository, sqlx::SqlitePool) {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };
    (repo, pool)
}

async fn build_sqlite_test_repo_only() -> SqliteRepository {
    let (repo, _) = build_sqlite_test_repo().await;
    repo
}

async fn insert_test_client(pool: &sqlx::SqlitePool, client_id: &str, public_keys: &str) {
    sqlx::query(
        "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', $2, 'kid-1', '[]')",
    )
    .bind(client_id)
    .bind(public_keys)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_test_request(pool: &sqlx::SqlitePool, request_id: &str) {
    sqlx::query(
        "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids) VALUES ($1, 'created', '2027-01-01T00:00:00Z', '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', '{}')",
    )
    .bind(request_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_request_with_status(
    pool: &sqlx::SqlitePool,
    request_id: &str,
    status: &str,
    expired: &str,
) {
    let (enc, sig) = match status {
        "created" => (None, None),
        "pending" => (Some("{}"), None),
        "approved" => (Some("{}"), Some("sig")),
        "denied" | "unavailable" => (Some("{}"), None),
        _ => (None, None),
    };
    sqlx::query(
        "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, unavailable_client_ids, encrypted_payloads, signature) VALUES ($1, $2, $3, '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', '{}', '[]', $4, $5)",
    )
    .bind(request_id)
    .bind(status)
    .bind(expired)
    .bind(enc)
    .bind(sig)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_request_with_e2e_kids(
    pool: &sqlx::SqlitePool,
    request_id: &str,
    status: &str,
    e2e_kids: &str,
) {
    let enc = match status {
        "pending" | "approved" | "denied" | "unavailable" => Some("{}"),
        _ => None,
    };
    let sig = match status {
        "approved" => Some("sig"),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, unavailable_client_ids, encrypted_payloads, signature) VALUES ($1, $2, '2027-01-01T00:00:00Z', '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', $3, '[]', $4, $5)",
    )
    .bind(request_id)
    .bind(status)
    .bind(e2e_kids)
    .bind(enc)
    .bind(sig)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_audit_log(
    pool: &sqlx::SqlitePool,
    log_id: &str,
    event_type: &str,
    timestamp: &str,
) {
    sqlx::query(
        "INSERT INTO audit_log (log_id, timestamp, event_type, request_id) \
         VALUES ($1, $2, $3, 'req-1')",
    )
    .bind(log_id)
    .bind(timestamp)
    .bind(event_type)
    .execute(pool)
    .await
    .unwrap();
}

async fn count_audit_logs(pool: &sqlx::SqlitePool) -> i32 {
    sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM audit_log")
        .fetch_one(pool)
        .await
        .unwrap()
}
