use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn create_client_pairing_inserts_row(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let pairings = repo.get_client_pairings("c1").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "p1");
    assert_eq!(pairings[0].client_jwt_issued_at, "2026-01-01T00:00:00Z");
}
repo_test!(create_client_pairing_inserts_row);

async fn delete_client_pairing_removes_row(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo.delete_client_pairing("c1", "p1").await.unwrap();
    assert!(deleted);
    assert!(repo.get_client_pairings("c1").await.unwrap().is_empty());
}
repo_test!(delete_client_pairing_removes_row);

async fn delete_client_pairing_returns_false_for_missing(f: &dyn TestFixture) {
    let repo = f.repo();

    let deleted = repo.delete_client_pairing("c1", "p1").await.unwrap();
    assert!(!deleted);
}
repo_test!(delete_client_pairing_returns_false_for_missing);

async fn delete_client_pairing_and_cleanup_deletes_client_when_last_pairing(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let (pairing_deleted, client_deleted) = repo
        .delete_client_pairing_and_cleanup("c1", "p1")
        .await
        .unwrap();
    assert!(pairing_deleted);
    assert!(client_deleted);
    assert!(repo.get_client_by_id("c1").await.unwrap().is_none());
}
repo_test!(delete_client_pairing_and_cleanup_deletes_client_when_last_pairing);

async fn delete_client_pairing_and_cleanup_keeps_client_when_other_pairings_remain(
    f: &dyn TestFixture,
) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.create_client_pairing("c1", "p2", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let (pairing_deleted, client_deleted) = repo
        .delete_client_pairing_and_cleanup("c1", "p1")
        .await
        .unwrap();
    assert!(pairing_deleted);
    assert!(!client_deleted);
    assert!(repo.get_client_by_id("c1").await.unwrap().is_some());
}
repo_test!(delete_client_pairing_and_cleanup_keeps_client_when_other_pairings_remain);

async fn update_client_jwt_issued_at_updates_timestamp(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let updated = repo
        .update_client_jwt_issued_at("c1", "p1", "2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert!(updated);

    let pairings = repo.get_client_pairings("c1").await.unwrap();
    assert_eq!(pairings[0].client_jwt_issued_at, "2026-06-01T00:00:00Z");
}
repo_test!(update_client_jwt_issued_at_updates_timestamp);

async fn update_client_jwt_issued_at_returns_false_for_missing(f: &dyn TestFixture) {
    let repo = f.repo();

    let updated = repo
        .update_client_jwt_issued_at("c1", "p1", "2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert!(!updated);
}
repo_test!(update_client_jwt_issued_at_returns_false_for_missing);

async fn get_client_pairings_returns_matching(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    repo.create_client_pairing("client-1", "pair-1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let pairings = repo.get_client_pairings("client-1").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "pair-1");
}
repo_test!(get_client_pairings_returns_matching);

async fn get_client_pairings_returns_empty_for_unknown(f: &dyn TestFixture) {
    let repo = f.repo();

    let pairings = repo.get_client_pairings("nonexistent").await.unwrap();
    assert!(pairings.is_empty());
}
repo_test!(get_client_pairings_returns_empty_for_unknown);
