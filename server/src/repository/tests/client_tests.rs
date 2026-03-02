use crate::repository::ClientRow;

use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn create_client_inserts_row(f: &dyn TestFixture) {
    let repo = f.repo();

    let row = ClientRow {
        client_id: "c-new".to_owned(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        updated_at: "2026-01-01T00:00:00Z".to_owned(),
        device_token: "tok-new".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00Z".to_owned(),
        public_keys: "[]".to_owned(),
        default_kid: "kid-1".to_owned(),
        gpg_keys: "[]".to_owned(),
    };
    repo.create_client(&row).await.unwrap();

    let fetched = repo.get_client_by_id("c-new").await.unwrap().unwrap();
    assert_eq!(fetched.client_id, "c-new");
    assert_eq!(fetched.device_token, "tok-new");
}
repo_test!(create_client_inserts_row);

async fn get_client_by_id_found(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.client_id, "client-1");
}
repo_test!(get_client_by_id_found);

async fn get_client_by_id_not_found(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(
        repo.get_client_by_id("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}
repo_test!(get_client_by_id_not_found);

async fn client_exists_returns_true_for_existing_client(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    assert!(repo.client_exists("client-1").await.unwrap());
}
repo_test!(client_exists_returns_true_for_existing_client);

async fn client_exists_returns_false_for_missing_client(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(!repo.client_exists("nonexistent").await.unwrap());
}
repo_test!(client_exists_returns_false_for_missing_client);

async fn client_by_device_token_returns_matching_client(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let client = repo
        .client_by_device_token("tok")
        .await
        .unwrap()
        .expect("should find client by device_token");
    assert_eq!(client.client_id, "client-1");
}
repo_test!(client_by_device_token_returns_matching_client);

async fn client_by_device_token_returns_none_for_unknown(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(
        repo.client_by_device_token("unknown")
            .await
            .unwrap()
            .is_none()
    );
}
repo_test!(client_by_device_token_returns_none_for_unknown);

async fn update_client_device_token_persists_change(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    repo.update_client_device_token("client-1", "new-tok", "2026-06-01T00:00:00Z")
        .await
        .unwrap();

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.device_token, "new-tok");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}
repo_test!(update_client_device_token_persists_change);

async fn update_client_default_kid_persists_change(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    repo.update_client_default_kid("client-1", "kid-new", "2026-06-01T00:00:00Z")
        .await
        .unwrap();

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.default_kid, "kid-new");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}
repo_test!(update_client_default_kid_persists_change);

async fn delete_client_removes_row(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    assert!(repo.get_client_by_id("client-1").await.unwrap().is_some());

    repo.delete_client("client-1").await.unwrap();
    assert!(repo.get_client_by_id("client-1").await.unwrap().is_none());
}
repo_test!(delete_client_removes_row);

async fn update_client_public_keys_succeeds_with_matching_version(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let ok = repo
        .update_client_public_keys(
            "client-1",
            "[{\"kid\":\"k2\"}]",
            "k2",
            "2026-06-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(ok);

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.public_keys, "[{\"kid\":\"k2\"}]");
    assert_eq!(client.default_kid, "k2");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}
repo_test!(update_client_public_keys_succeeds_with_matching_version);

async fn update_client_public_keys_fails_with_stale_version(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let ok = repo
        .update_client_public_keys(
            "client-1",
            "[{\"kid\":\"k2\"}]",
            "k2",
            "2026-06-01T00:00:00Z",
            "1999-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(!ok);

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.public_keys, "[]");
}
repo_test!(update_client_public_keys_fails_with_stale_version);

async fn update_client_gpg_keys_succeeds_with_matching_version(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let ok = repo
        .update_client_gpg_keys(
            "client-1",
            "[{\"fingerprint\":\"abc\"}]",
            "2026-06-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(ok);

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.gpg_keys, "[{\"fingerprint\":\"abc\"}]");
    assert_eq!(client.updated_at, "2026-06-01T00:00:00Z");
}
repo_test!(update_client_gpg_keys_succeeds_with_matching_version);

async fn update_client_gpg_keys_fails_with_stale_version(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    let ok = repo
        .update_client_gpg_keys(
            "client-1",
            "[{\"fingerprint\":\"abc\"}]",
            "2026-06-01T00:00:00Z",
            "1999-01-01T00:00:00Z",
        )
        .await
        .unwrap();
    assert!(!ok);

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.gpg_keys, "[]");
}
repo_test!(update_client_gpg_keys_fails_with_stale_version);

async fn update_device_jwt_issued_at_persists_change(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_client(repo, "client-1", "[]").await;
    repo.update_device_jwt_issued_at("client-1", "2026-06-15T00:00:00Z", "2026-06-15T00:00:00Z")
        .await
        .unwrap();

    let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
    assert_eq!(client.device_jwt_issued_at, "2026-06-15T00:00:00Z");
}
repo_test!(update_device_jwt_issued_at_persists_change);
