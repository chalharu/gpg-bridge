use crate::repository::build_repository;

use super::sqlite_test_config;

#[tokio::test]
async fn sqlite_repository_runs_migration_and_health_check() {
    let config = sqlite_test_config();
    let repository = build_repository(&config).await.unwrap();

    repository.run_migrations().await.unwrap();
    repository.health_check().await.unwrap();
    assert_eq!(repository.backend_name(), "sqlite");
}

#[tokio::test]
async fn run_migrations_creates_tables() {
    let (_repo, pool) = super::build_sqlite_test_repo().await;

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

#[tokio::test]
async fn sqlite_enforces_foreign_key_constraints() {
    let (_repo, pool) = super::build_sqlite_test_repo().await;

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
