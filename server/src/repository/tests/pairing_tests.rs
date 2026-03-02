use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn create_and_get_pairing(f: &dyn TestFixture) {
    let repo = f.repo();

    repo.create_pairing("pair-1", "2027-01-01T00:00:00Z")
        .await
        .unwrap();

    let row = repo.get_pairing_by_id("pair-1").await.unwrap().unwrap();
    assert_eq!(row.pairing_id, "pair-1");
    assert_eq!(row.expired, "2027-01-01T00:00:00Z");
    assert!(row.client_id.is_none());
}
repo_test!(create_and_get_pairing);

async fn get_pairing_by_id_returns_none_for_unknown(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(repo.get_pairing_by_id("nope").await.unwrap().is_none());
}
repo_test!(get_pairing_by_id_returns_none_for_unknown);

async fn consume_pairing_succeeds_when_unconsumed(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    repo.create_pairing("pair-1", "2027-01-01T00:00:00Z")
        .await
        .unwrap();

    let consumed = repo.consume_pairing("pair-1", "client-1").await.unwrap();
    assert!(consumed);

    let row = repo.get_pairing_by_id("pair-1").await.unwrap().unwrap();
    assert_eq!(row.client_id.as_deref(), Some("client-1"));
}
repo_test!(consume_pairing_succeeds_when_unconsumed);

async fn consume_pairing_fails_when_already_consumed(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    helpers::insert_test_client(repo, "client-2", "[]").await;
    repo.create_pairing("pair-1", "2027-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.consume_pairing("pair-1", "client-1").await.unwrap();

    let consumed = repo.consume_pairing("pair-1", "client-2").await.unwrap();
    assert!(!consumed);

    // Original consumer unchanged
    let row = repo.get_pairing_by_id("pair-1").await.unwrap().unwrap();
    assert_eq!(row.client_id.as_deref(), Some("client-1"));
}
repo_test!(consume_pairing_fails_when_already_consumed);

async fn count_unconsumed_pairings_only_counts_active(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;

    // Two unconsumed pairings (one future, one past)
    repo.create_pairing("future", "2027-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.create_pairing("past", "2025-01-01T00:00:00Z")
        .await
        .unwrap();

    // One consumed pairing
    repo.create_pairing("consumed", "2027-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.consume_pairing("consumed", "client-1").await.unwrap();

    let count = repo
        .count_unconsumed_pairings("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    // Only "future" is unconsumed AND not expired
    assert_eq!(count, 1);
}
repo_test!(count_unconsumed_pairings_only_counts_active);

async fn delete_expired_pairings_removes_old(f: &dyn TestFixture) {
    let repo = f.repo();

    repo.create_pairing("old", "2025-01-01T00:00:00Z")
        .await
        .unwrap();
    repo.create_pairing("fresh", "2027-01-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo
        .delete_expired_pairings("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(repo.get_pairing_by_id("old").await.unwrap().is_none());
    assert!(repo.get_pairing_by_id("fresh").await.unwrap().is_some());
}
repo_test!(delete_expired_pairings_removes_old);
