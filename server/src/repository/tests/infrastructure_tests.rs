use crate::repository::build_repository;

use super::fixture::{SqliteTestFixture, TestFixture};
use super::repo_test;
use super::sqlite_test_config;

#[tokio::test]
async fn sqlite_repository_runs_migration_and_health_check() {
    let config = sqlite_test_config();
    let repository = build_repository(&config).await.unwrap();

    repository.run_migrations().await.unwrap();
    repository.health_check().await.unwrap();
    assert_eq!(repository.backend_name(), "sqlite");
}

async fn run_migrations_creates_tables(f: &dyn TestFixture) {
    // Verify that the clients table exists by querying it.
    let count = f.count_table_rows("clients").await;
    assert_eq!(count, 0);

    // Verify that the signing_keys table exists.
    let count = f.count_table_rows("signing_keys").await;
    assert_eq!(count, 0);
}
repo_test!(run_migrations_creates_tables);

#[tokio::test]
async fn sqlite_enforces_foreign_key_constraints() {
    let f = SqliteTestFixture::setup().await;

    // Positive case: insert a valid client, then a client_pairings row referencing it.
    sqlx::query(
        "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ('client-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', '[]', 'kid-1', '[]')",
    )
    .execute(&f.pool)
    .await
    .expect("inserting a valid client should succeed");

    sqlx::query(
        "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
    )
    .execute(&f.pool)
    .await
    .expect("inserting a client_pairings row with valid FK should succeed");

    // Negative case: inserting a client_pairings row referencing a non-existent client
    // must fail because of the foreign key constraint on client_id.
    let result = sqlx::query(
        "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('nonexistent', 'pair-2', '2026-01-01T00:00:00Z')",
    )
    .execute(&f.pool)
    .await;

    let err = result
        .expect_err("foreign key constraint should reject insert with non-existent client_id");
    let msg = err.to_string();
    assert!(
        msg.contains("FOREIGN KEY constraint failed"),
        "expected FK violation error, got: {msg}",
    );
}
