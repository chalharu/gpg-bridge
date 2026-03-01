use crate::repository::JtiRepository;

#[tokio::test]
async fn store_jti_returns_true_for_new() {
    let repo = super::build_sqlite_test_repo_only().await;

    assert!(
        repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn store_jti_returns_false_for_duplicate() {
    let repo = super::build_sqlite_test_repo_only().await;

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
    let repo = super::build_sqlite_test_repo_only().await;

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
