use crate::repository::AuditLogRow;

use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn create_audit_log_inserts_row(f: &dyn TestFixture) {
    let repo = f.repo();

    let row = AuditLogRow {
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
    assert_eq!(f.count_table_rows("audit_log").await, 1);
}
repo_test!(create_audit_log_inserts_row);

async fn delete_expired_audit_logs_by_retention(f: &dyn TestFixture) {
    let repo = f.repo();

    // approved (1yr retention): old=2024, new=2026
    helpers::insert_audit_log(repo, "a1", "sign_approved", "2024-01-01T00:00:00Z").await;
    helpers::insert_audit_log(repo, "a2", "sign_approved", "2026-01-01T00:00:00Z").await;
    // created (1yr retention)
    helpers::insert_audit_log(repo, "a3", "sign_request_created", "2024-01-01T00:00:00Z").await;
    // denied (6mo retention): old=2025-01, new=2026
    helpers::insert_audit_log(repo, "a4", "sign_denied", "2025-01-01T00:00:00Z").await;
    helpers::insert_audit_log(repo, "a5", "sign_denied", "2026-01-01T00:00:00Z").await;
    // expired (6mo retention)
    helpers::insert_audit_log(repo, "a6", "sign_expired", "2025-03-01T00:00:00Z").await;
    // cancelled (6mo retention)
    helpers::insert_audit_log(repo, "a7", "sign_cancelled", "2025-02-01T00:00:00Z").await;
    // conflict (3mo retention): old=2025-09, new=2026
    helpers::insert_audit_log(repo, "a8", "sign_result_conflict", "2025-09-01T00:00:00Z").await;
    helpers::insert_audit_log(repo, "a9", "sign_result_conflict", "2026-01-01T00:00:00Z").await;
    // device_unavailable (6mo)
    helpers::insert_audit_log(
        repo,
        "a10",
        "sign_device_unavailable",
        "2025-01-01T00:00:00Z",
    )
    .await;
    // unavailable (6mo)
    helpers::insert_audit_log(repo, "a11", "sign_unavailable", "2025-02-01T00:00:00Z").await;

    assert_eq!(f.count_table_rows("audit_log").await, 11);

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
    assert_eq!(f.count_table_rows("audit_log").await, 3);
}
repo_test!(delete_expired_audit_logs_by_retention);

async fn delete_expired_audit_logs_returns_zero_when_empty(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(delete_expired_audit_logs_returns_zero_when_empty);
