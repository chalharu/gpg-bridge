use super::fixture::TestFixture;
use super::repo_test;

fn assert_pool_closed_error(err: &anyhow::Error, context_fragment: &str) {
    assert!(
        err.chain().any(|cause| matches!(
            cause.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::PoolClosed)
        )),
        "expected pool closed root cause, got: {err:#}",
    );
    assert!(
        err.to_string().contains(context_fragment),
        "expected context fragment '{context_fragment}' in error, got: {err:#}",
    );
}

async fn repository_runs_migration_and_health_check(f: &dyn TestFixture) {
    let repository = f.repo();

    repository.run_migrations().await.unwrap();
    repository.health_check().await.unwrap();
    assert_eq!(repository.backend_name(), f.backend_name());
}
repo_test!(repository_runs_migration_and_health_check);

async fn run_migrations_fails_when_pool_is_closed(f: &dyn TestFixture) {
    f.close_pool().await;

    let err = f
        .repo()
        .run_migrations()
        .await
        .expect_err("run_migrations should fail after the pool is closed");

    assert_pool_closed_error(
        &err,
        &format!("failed to run {} migrations", f.backend_name()),
    );
}
repo_test!(run_migrations_fails_when_pool_is_closed);

async fn health_check_fails_when_pool_is_closed(f: &dyn TestFixture) {
    f.close_pool().await;

    let err = f
        .repo()
        .health_check()
        .await
        .expect_err("health_check should fail after the pool is closed");

    assert_pool_closed_error(&err, &format!("{} health check failed", f.backend_name()));
}
repo_test!(health_check_fails_when_pool_is_closed);

async fn run_migrations_creates_tables(f: &dyn TestFixture) {
    // Verify that the clients table exists by querying it.
    let count = f.count_table_rows("clients").await;
    assert_eq!(count, 0);

    // Verify that the signing_keys table exists.
    let count = f.count_table_rows("signing_keys").await;
    assert_eq!(count, 0);
}
repo_test!(run_migrations_creates_tables);

async fn repository_enforces_foreign_key_constraints(f: &dyn TestFixture) {
    // Positive case: insert a valid client, then a client_pairings row referencing it.
    f.execute_sql(
        "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ('client-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', '[]', 'kid-1', '[]')",
    )
    .await
    .expect("inserting a valid client should succeed");

    f.execute_sql(
        "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
    )
    .await
    .expect("inserting a client_pairings row with valid FK should succeed");

    // Negative case: inserting a client_pairings row referencing a non-existent client
    // must fail because of the foreign key constraint on client_id.
    let err = f
        .execute_sql(
        "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('nonexistent', 'pair-2', '2026-01-01T00:00:00Z')",
        )
        .await
        .expect_err("foreign key constraint should reject insert with non-existent client_id");

    let msg = err.to_string();
    assert!(
        msg.contains(f.foreign_key_error_fragment()),
        "expected FK violation error, got: {msg}",
    );
}
repo_test!(repository_enforces_foreign_key_constraints);
