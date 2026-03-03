use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn delete_unpaired_clients_removes_old_without_pairings(f: &dyn TestFixture) {
    let repo = f.repo();

    // Old client without pairings
    helpers::insert_test_client(repo, "orphan", "[]").await;

    // Old client WITH pairings
    helpers::insert_test_client(repo, "paired", "[]").await;
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
repo_test!(delete_unpaired_clients_removes_old_without_pairings);

async fn delete_expired_device_jwt_clients_removes_old(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "old-jwt", "[]").await;
    helpers::insert_test_client(repo, "new-jwt", "[]").await;

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
repo_test!(delete_expired_device_jwt_clients_removes_old);

async fn delete_expired_client_jwt_pairings_removes_and_cascades(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
    helpers::insert_test_client(repo, "c2", "[]").await;

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
    assert_eq!(removed, 2);

    // c1 cascade-deleted
    assert!(repo.get_client_by_id("c1").await.unwrap().is_none());

    // c2 still has p-new
    assert!(repo.get_client_by_id("c2").await.unwrap().is_some());
    let pairings = repo.get_client_pairings("c2").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "p-new");
}
repo_test!(delete_expired_client_jwt_pairings_removes_and_cascades);

async fn delete_expired_client_jwt_pairings_noop_when_nothing_expired(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "c1", "[]").await;
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
repo_test!(delete_expired_client_jwt_pairings_noop_when_nothing_expired);
