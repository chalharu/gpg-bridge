use crate::repository::{SigningKeyRepository, SigningKeyRow};

fn make_signing_key_row(kid: &str, is_active: bool, expires_at: &str) -> SigningKeyRow {
    SigningKeyRow {
        kid: kid.to_owned(),
        private_key: "encrypted-private".to_owned(),
        public_key: "{\"kty\":\"EC\"}".to_owned(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        expires_at: expires_at.to_owned(),
        is_active,
    }
}

#[tokio::test]
async fn store_and_get_active_signing_key() {
    let repo = super::build_sqlite_test_repo_only().await;

    let key = make_signing_key_row("kid-1", true, "2027-01-01T00:00:00Z");
    repo.store_signing_key(&key).await.unwrap();

    let active = repo.get_active_signing_key().await.unwrap().unwrap();
    assert_eq!(active.kid, "kid-1");
    assert!(active.is_active);
}

#[tokio::test]
async fn get_signing_key_by_kid() {
    let repo = super::build_sqlite_test_repo_only().await;

    let key = make_signing_key_row("kid-2", false, "2027-01-01T00:00:00Z");
    repo.store_signing_key(&key).await.unwrap();

    let found = repo.get_signing_key_by_kid("kid-2").await.unwrap().unwrap();
    assert_eq!(found.kid, "kid-2");
    assert!(!found.is_active);

    let missing = repo.get_signing_key_by_kid("nonexistent").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn retire_signing_key_sets_inactive() {
    let repo = super::build_sqlite_test_repo_only().await;

    let key = make_signing_key_row("kid-3", true, "2027-01-01T00:00:00Z");
    repo.store_signing_key(&key).await.unwrap();

    let updated = repo.retire_signing_key("kid-3").await.unwrap();
    assert!(updated);

    let retired = repo.get_signing_key_by_kid("kid-3").await.unwrap().unwrap();
    assert!(!retired.is_active);
    assert!(repo.get_active_signing_key().await.unwrap().is_none());
}

#[tokio::test]
async fn retire_nonexistent_signing_key_returns_false() {
    let repo = super::build_sqlite_test_repo_only().await;

    let updated = repo.retire_signing_key("nonexistent").await.unwrap();
    assert!(!updated);
}

#[tokio::test]
async fn delete_expired_signing_keys_removes_old() {
    let repo = super::build_sqlite_test_repo_only().await;

    let expired = make_signing_key_row("kid-old", false, "2025-01-01T00:00:00Z");
    let valid = make_signing_key_row("kid-new", false, "2027-01-01T00:00:00Z");
    repo.store_signing_key(&expired).await.unwrap();
    repo.store_signing_key(&valid).await.unwrap();

    let deleted = repo
        .delete_expired_signing_keys("2026-06-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(
        repo.get_signing_key_by_kid("kid-old")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_signing_key_by_kid("kid-new")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn no_active_key_returns_none() {
    let repo = super::build_sqlite_test_repo_only().await;

    assert!(repo.get_active_signing_key().await.unwrap().is_none());
}
