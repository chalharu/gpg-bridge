use crate::repository::{ClientPairingRepository, ClientRepository};

#[tokio::test]
async fn create_client_pairing_inserts_row() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let pairings = repo.get_client_pairings("c1").await.unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].pairing_id, "p1");
    assert_eq!(pairings[0].client_jwt_issued_at, "2026-01-01T00:00:00Z");
}

#[tokio::test]
async fn delete_client_pairing_removes_row() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "c1", "[]").await;
    repo.create_client_pairing("c1", "p1", "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let deleted = repo.delete_client_pairing("c1", "p1").await.unwrap();
    assert!(deleted);
    assert!(repo.get_client_pairings("c1").await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_client_pairing_returns_false_for_missing() {
    let repo = super::build_sqlite_test_repo_only().await;

    let deleted = repo.delete_client_pairing("c1", "p1").await.unwrap();
    assert!(!deleted);
}

#[tokio::test]
async fn delete_client_pairing_and_cleanup_deletes_client_when_last_pairing() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "c1", "[]").await;
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

#[tokio::test]
async fn delete_client_pairing_and_cleanup_keeps_client_when_other_pairings_remain() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "c1", "[]").await;
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

#[tokio::test]
async fn update_client_jwt_issued_at_updates_timestamp() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "c1", "[]").await;
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

#[tokio::test]
async fn update_client_jwt_issued_at_returns_false_for_missing() {
    let repo = super::build_sqlite_test_repo_only().await;

    let updated = repo
        .update_client_jwt_issued_at("c1", "p1", "2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert!(!updated);
}

#[tokio::test]
async fn get_client_pairings_returns_matching() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_client(&pool, "client-1", "[]").await;
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
    let repo = super::build_sqlite_test_repo_only().await;

    let pairings = repo.get_client_pairings("nonexistent").await.unwrap();
    assert!(pairings.is_empty());
}
