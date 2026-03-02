use super::fixture::TestFixture;
use super::repo_test;

async fn store_jti_returns_true_for_new(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(
        repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap()
    );
}
repo_test!(store_jti_returns_true_for_new);

async fn store_jti_returns_false_for_duplicate(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(store_jti_returns_false_for_duplicate);

async fn delete_expired_jtis_removes_old(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(delete_expired_jtis_removes_old);
