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

// ---- clients repository tests ----

async fn insert_test_client(pool: &SqlitePool, client_id: &str, public_keys: &str) {
    sqlx::query(
        "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', $2, 'kid-1', '[]')",
    )
    .bind(client_id)
    .bind(public_keys)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn get_client_by_id_found() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.client_id, "client-1");
}

#[tokio::test]
async fn get_client_by_id_not_found() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(
        repo.get_client_by_id("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

// ---- client_pairings repository tests ----

#[tokio::test]
async fn get_client_pairings_returns_matching() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    sqlx::query(
        "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let pairings = repo.get_client_pairings("client-1").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "pair-1");
}

#[tokio::test]
async fn get_client_pairings_returns_empty_for_unknown() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    let pairings = repo.get_client_pairings("nonexistent").await.unwrap();
    assert!(pairings.is_empty());
}

// ---- requests repository tests ----

async fn insert_test_request(pool: &SqlitePool, request_id: &str) {
    sqlx::query(
        "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids) VALUES ($1, 'created', '2027-01-01T00:00:00Z', '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', '{}')",
    )
    .bind(request_id)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn get_request_by_id_found() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_request(&pool, "req-1").await;
    let request = repo.get_request_by_id("req-1").await.unwrap().unwrap();
    assert_eq!(request.request_id, "req-1");
    assert_eq!(request.status, "created");
}

#[tokio::test]
async fn get_request_by_id_not_found() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(
        repo.get_request_by_id("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

// ---- jtis repository tests ----

#[tokio::test]
async fn store_jti_returns_true_for_new() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(
        repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn store_jti_returns_false_for_duplicate() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(
        repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
    assert!(
        !repo
            .store_jti("jti-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn delete_expired_jtis_removes_old() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    repo.store_jti("jti-old", "2025-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.store_jti("jti-new", "2027-01-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo
        .delete_expired_jtis("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    // jti-old was deleted, so storing it again should succeed
    assert!(
        repo.store_jti("jti-old", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
    // jti-new still exists
    assert!(
        !repo
            .store_jti("jti-new", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
}

// ---- audit_log repository tests ----

async fn insert_audit_log(pool: &SqlitePool, log_id: &str, event_type: &str, timestamp: &str) {
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

async fn count_audit_logs(pool: &SqlitePool) -> i32 {
    sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM audit_log")
        .fetch_one(pool)
        .await
        .unwrap()
}

// ---- delete_expired_requests tests ----

async fn insert_request_with_status(
    pool: &SqlitePool,
    request_id: &str,
    status: &str,
    expired: &str,
) {
    // The CHECK constraint requires specific column combinations per status.
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

#[tokio::test]
async fn create_audit_log_inserts_row() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    let row = super::AuditLogRow {
        log_id: "log-1".into(),
        timestamp: "2026-06-01T00:00:00Z".into(),
        event_type: "sign_approved".into(),
        request_id: "req-1".into(),
        request_ip: None,
        target_client_ids: None,
        responding_client_id: Some("client-1".into()),
        error_code: None,
        error_message: None,
    };
    repo.create_audit_log(&row).await.unwrap();
    assert_eq!(count_audit_logs(&pool).await, 1);
}

#[tokio::test]
async fn delete_expired_audit_logs_by_retention() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    // approved (1yr retention): old=2024, new=2026
    insert_audit_log(&pool, "a1", "sign_approved", "2024-01-01T00:00:00Z").await;
    insert_audit_log(&pool, "a2", "sign_approved", "2026-01-01T00:00:00Z").await;
    // created (1yr retention)
    insert_audit_log(&pool, "a3", "sign_request_created", "2024-01-01T00:00:00Z").await;
    // denied (6mo retention): old=2025-01, new=2026
    insert_audit_log(&pool, "a4", "sign_denied", "2025-01-01T00:00:00Z").await;
    insert_audit_log(&pool, "a5", "sign_denied", "2026-01-01T00:00:00Z").await;
    // expired (6mo retention)
    insert_audit_log(&pool, "a6", "sign_expired", "2025-03-01T00:00:00Z").await;
    // cancelled (6mo retention)
    insert_audit_log(&pool, "a7", "sign_cancelled", "2025-02-01T00:00:00Z").await;
    // conflict (3mo retention): old=2025-09, new=2026
    insert_audit_log(&pool, "a8", "sign_result_conflict", "2025-09-01T00:00:00Z").await;
    insert_audit_log(&pool, "a9", "sign_result_conflict", "2026-01-01T00:00:00Z").await;
    // device_unavailable (6mo)
    insert_audit_log(
        &pool,
        "a10",
        "sign_device_unavailable",
        "2025-01-01T00:00:00Z",
    )
    .await;
    // unavailable (6mo)
    insert_audit_log(&pool, "a11", "sign_unavailable", "2025-02-01T00:00:00Z").await;

    assert_eq!(count_audit_logs(&pool).await, 11);

    // Cutoffs: approved_before=2025-06-01, denied_before=2025-12-01, conflict_before=2025-12-01
    let deleted = repo
        .delete_expired_audit_logs(
            "2025-06-01T00:00:00Z",
            "2025-12-01T00:00:00Z",
            "2025-12-01T00:00:00Z",
        )
        .await
        .unwrap();

    // Deleted: a1 (approved old), a3 (created old), a4 (denied old),
    //          a6 (expired old), a7 (cancelled old), a8 (conflict old),
    //          a10 (device_unavailable old), a11 (unavailable old) = 8
    assert_eq!(deleted, 8);
    // Remaining: a2, a5, a9 = 3
    assert_eq!(count_audit_logs(&pool).await, 3);
}

#[tokio::test]
async fn delete_expired_audit_logs_returns_zero_when_empty() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    let deleted = repo
        .delete_expired_audit_logs(
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert_eq!(deleted, 0);
}

#[tokio::test]
async fn delete_expired_requests_returns_incomplete_ids() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_request_with_status(&pool, "r-created", "created", "2025-01-01T00:00:00Z").await;
    insert_request_with_status(&pool, "r-pending", "pending", "2025-01-01T00:00:00Z").await;
    insert_request_with_status(&pool, "r-approved", "approved", "2025-01-01T00:00:00Z").await;
    insert_request_with_status(&pool, "r-future", "created", "2027-01-01T00:00:00Z").await;

    let mut ids = repo
        .delete_expired_requests("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    ids.sort();
    assert_eq!(ids, vec!["r-created", "r-pending"]);

    // r-approved also deleted, r-future remains
    assert!(
        repo.get_request_by_id("r-approved")
            .await
            .unwrap()
            .is_none()
    );
    assert!(repo.get_request_by_id("r-future").await.unwrap().is_some());
}

#[tokio::test]
async fn delete_expired_requests_empty_when_none() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    let ids = repo
        .delete_expired_requests("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    assert!(ids.is_empty());
}

// ---- delete_unpaired_clients tests ----

#[tokio::test]
async fn delete_unpaired_clients_removes_old_without_pairings() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    // Old client without pairings
    insert_test_client(&pool, "orphan", "[]").await;

    // Old client WITH pairings
    insert_test_client(&pool, "paired", "[]").await;
    repo.create_client_pairing("paired", "p-1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo
        .delete_unpaired_clients("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(repo.get_client_by_id("orphan").await.unwrap().is_none());
    assert!(repo.get_client_by_id("paired").await.unwrap().is_some());
}

// ---- delete_expired_device_jwt_clients tests ----

#[tokio::test]
async fn delete_expired_device_jwt_clients_removes_old() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "old-jwt", "[]").await;
    insert_test_client(&pool, "new-jwt", "[]").await;

    // new-jwt gets a fresh device_jwt_issued_at
    repo.update_device_jwt_issued_at("new-jwt", "2026-12-01T00:00:00Z", "2026-12-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo
        .delete_expired_device_jwt_clients("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(repo.get_client_by_id("old-jwt").await.unwrap().is_none());
    assert!(repo.get_client_by_id("new-jwt").await.unwrap().is_some());
}

// ---- delete_expired_client_jwt_pairings tests ----

#[tokio::test]
async fn delete_expired_client_jwt_pairings_removes_and_cascades() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "c1", "[]").await;
    insert_test_client(&pool, "c2", "[]").await;

    // c1 has one old pairing → will be removed → client deleted
    repo.create_client_pairing("c1", "p-old", "2025-01-01T00:00:00Z")
        .await
        .unwrap();

    // c2 has one old + one fresh → only old removed, client stays
    repo.create_client_pairing("c2", "p-old2", "2025-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.create_client_pairing("c2", "p-new", "2026-12-01T00:00:00Z")
        .await
        .unwrap();

    let removed = repo
        .delete_expired_client_jwt_pairings("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(removed, 2); // p-old + p-old2

    // c1 cascade-deleted
    assert!(repo.get_client_by_id("c1").await.unwrap().is_none());

    // c2 still has p-new
    assert!(repo.get_client_by_id("c2").await.unwrap().is_some());
    let pairings = repo.get_client_pairings("c2").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "p-new");
}

#[tokio::test]
async fn delete_expired_client_jwt_pairings_noop_when_nothing_expired() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "c1", "[]").await;
    repo.create_client_pairing("c1", "p-1", "2027-01-01T00:00:00Z")
        .await
        .unwrap();

    let removed = repo
        .delete_expired_client_jwt_pairings("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(removed, 0);
    assert!(repo.get_client_by_id("c1").await.unwrap().is_some());
}

// ---- run_migrations tests ----

#[tokio::test]
async fn run_migrations_creates_tables() {
    let pool = build_sqlite_test_pool().await;
    let repo = SqliteRepository { pool: pool.clone() };
    repo.run_migrations().await.unwrap();

    // Verify that the clients table exists by querying it.
    let count = sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM clients")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    // Verify that the signing_keys table exists.
    let count = sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM signing_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

// ---- client_exists tests ----

#[tokio::test]
async fn client_exists_returns_true_for_existing_client() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    assert!(repo.client_exists("client-1").await.unwrap());
}

#[tokio::test]
async fn client_exists_returns_false_for_missing_client() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(!repo.client_exists("nonexistent").await.unwrap());
}

// ---- client_by_device_token tests ----

#[tokio::test]
async fn client_by_device_token_returns_matching_client() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    // insert_test_client uses device_token = 'tok'
    let client = repo
        .client_by_device_token("tok")
        .await
        .unwrap()
        .expect("should find client by device_token");
    assert_eq!(client.client_id, "client-1");
}

#[tokio::test]
async fn client_by_device_token_returns_none_for_unknown() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool };

    assert!(
        repo.client_by_device_token("unknown")
            .await
            .unwrap()
            .is_none()
    );
}

// ---- update_client_device_token tests ----

#[tokio::test]
async fn update_client_device_token_persists_change() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    repo.update_client_device_token("client-1", "new-tok", "2026-06-01T00:00:00Z")
        .await
        .unwrap();

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.device_token, "new-tok");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}

// ---- update_client_default_kid tests ----

#[tokio::test]
async fn update_client_default_kid_persists_change() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    repo.update_client_default_kid("client-1", "kid-new", "2026-06-01T00:00:00Z")
        .await
        .unwrap();

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.default_kid, "kid-new");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}

// ---- delete_client tests ----

#[tokio::test]
async fn delete_client_removes_row() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    assert!(repo.get_client_by_id("client-1").await.unwrap().is_some());

    repo.delete_client("client-1").await.unwrap();
    assert!(repo.get_client_by_id("client-1").await.unwrap().is_none());
}

// ---- update_client_public_keys tests ----

#[tokio::test]
async fn update_client_public_keys_succeeds_with_matching_version() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    // insert_test_client sets updated_at = '2026-01-01T00:00:00Z'
    let ok = repo
        .update_client_public_keys(
            "client-1",
            "[{\"kid\":\"k2\"}]",
            "k2",
            "2026-06-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(ok);

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.public_keys, "[{\"kid\":\"k2\"}]");
    assert_eq!(client.default_kid, "k2");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}

#[tokio::test]
async fn update_client_public_keys_fails_with_stale_version() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_test_client(&pool, "client-1", "[]").await;
    let ok = repo
        .update_client_public_keys(
            "client-1",
            "[{\"kid\":\"k2\"}]",
            "k2",
            "2026-06-01T00:00:00Z",
            "1999-01-01T00:00:00Z", // stale expected_updated_at
        )
        .await
        .unwrap();
    assert!(!ok);

    // Original data unchanged
    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.public_keys, "[]");
}

// ---- is_kid_in_flight tests ----

async fn insert_request_with_e2e_kids(
    pool: &SqlitePool,
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

#[tokio::test]
async fn is_kid_in_flight_returns_true_when_request_has_matching_kid() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    insert_request_with_e2e_kids(&pool, "req-1", "created", r#"["kid-test","kid-other"]"#).await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}

#[tokio::test]
async fn is_kid_in_flight_returns_false_when_no_matching_request() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    // No requests at all
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // Request exists but with a different kid
    insert_request_with_e2e_kids(&pool, "req-1", "created", r#"["kid-other"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());
}

#[tokio::test]
async fn is_kid_in_flight_ignores_non_active_statuses() {
    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    let repo = SqliteRepository { pool: pool.clone() };

    // approved request should NOT count
    insert_request_with_e2e_kids(&pool, "req-1", "approved", r#"["kid-test"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // pending request SHOULD count
    insert_request_with_e2e_kids(&pool, "req-2", "pending", r#"["kid-test"]"#).await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}
