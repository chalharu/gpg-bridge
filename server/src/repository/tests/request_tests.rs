use crate::repository::{CreateRequestRow, RequestRepository};

#[tokio::test]
async fn get_request_by_id_found() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_test_request(&pool, "req-1").await;
    let request = repo.get_request_by_id("req-1").await.unwrap().unwrap();
    assert_eq!(request.request_id, "req-1");
    assert_eq!(request.status, "created");
}

#[tokio::test]
async fn get_request_by_id_not_found() {
    let repo = super::build_sqlite_test_repo_only().await;

    assert!(
        repo.get_request_by_id("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delete_expired_requests_returns_incomplete_ids() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_request_with_status(&pool, "r-created", "created", "2025-01-01T00:00:00Z").await;
    super::insert_request_with_status(&pool, "r-pending", "pending", "2025-01-01T00:00:00Z").await;
    super::insert_request_with_status(&pool, "r-approved", "approved", "2025-01-01T00:00:00Z")
        .await;
    super::insert_request_with_status(&pool, "r-future", "created", "2027-01-01T00:00:00Z").await;

    let mut ids = repo
        .delete_expired_requests("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    ids.sort();
    assert_eq!(ids, vec!["r-created", "r-pending"]);

    // r-approved also deleted, r-future remains
    assert!(
        repo.get_request_by_id("r-approved")
            .await
            .unwrap()
            .is_none()
    );
    assert!(repo.get_request_by_id("r-future").await.unwrap().is_some());
}

#[tokio::test]
async fn delete_expired_requests_empty_when_none() {
    let repo = super::build_sqlite_test_repo_only().await;

    let ids = repo
        .delete_expired_requests("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    assert!(ids.is_empty());
}

#[tokio::test]
async fn is_kid_in_flight_returns_true_when_request_has_matching_kid() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    super::insert_request_with_e2e_kids(&pool, "req-1", "created", r#"["kid-test","kid-other"]"#)
        .await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}

#[tokio::test]
async fn is_kid_in_flight_returns_false_when_no_matching_request() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    // No requests at all
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // Request exists but with a different kid
    super::insert_request_with_e2e_kids(&pool, "req-1", "created", r#"["kid-other"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());
}

#[tokio::test]
async fn is_kid_in_flight_ignores_non_active_statuses() {
    let (repo, pool) = super::build_sqlite_test_repo().await;

    // approved request should NOT count
    super::insert_request_with_e2e_kids(&pool, "req-1", "approved", r#"["kid-test"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // pending request SHOULD count
    super::insert_request_with_e2e_kids(&pool, "req-2", "pending", r#"["kid-test"]"#).await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}

#[tokio::test]
async fn create_request_and_get_full() {
    let repo = super::build_sqlite_test_repo_only().await;

    let row = CreateRequestRow {
        request_id: "req-new".to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[\"c1\"]".to_owned(),
        daemon_public_key: "{\"kty\":\"EC\"}".to_owned(),
        daemon_enc_public_key: "{\"kty\":\"EC\"}".to_owned(),
        pairing_ids: "{\"c1\":\"p1\"}".to_owned(),
        e2e_kids: "[\"kid-1\"]".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    };
    repo.create_request(&row).await.unwrap();

    let full = repo
        .get_full_request_by_id("req-new")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.request_id, "req-new");
    assert_eq!(full.status, "created");
    assert_eq!(full.client_ids, "[\"c1\"]");
    assert!(full.signature.is_none());
    assert!(full.encrypted_payloads.is_none());
}

#[tokio::test]
async fn update_request_phase2_cas() {
    let repo = super::build_sqlite_test_repo_only().await;

    let row = CreateRequestRow {
        request_id: "req-1".to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[]".to_owned(),
        daemon_public_key: "{\"kty\":\"EC\"}".to_owned(),
        daemon_enc_public_key: "{\"kty\":\"EC\"}".to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: "[]".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    };
    repo.create_request(&row).await.unwrap();

    let ok = repo.update_request_phase2("req-1", "{}").await.unwrap();
    assert!(ok);

    // Status is now "pending" — second call should fail
    let ok = repo.update_request_phase2("req-1", "{}").await.unwrap();
    assert!(!ok);
}

#[tokio::test]
async fn update_request_approved_and_denied_cas() {
    let repo = super::build_sqlite_test_repo_only().await;

    for id in &["req-a", "req-d"] {
        let row = CreateRequestRow {
            request_id: id.to_string(),
            status: "created".to_owned(),
            expired: "2027-01-01T00:00:00Z".to_owned(),
            client_ids: "[]".to_owned(),
            daemon_public_key: "{\"kty\":\"EC\"}".to_owned(),
            daemon_enc_public_key: "{\"kty\":\"EC\"}".to_owned(),
            pairing_ids: "{}".to_owned(),
            e2e_kids: "[]".to_owned(),
            unavailable_client_ids: "[]".to_owned(),
        };
        repo.create_request(&row).await.unwrap();
        repo.update_request_phase2(id, "{}").await.unwrap();
    }

    let ok = repo.update_request_approved("req-a", "sig").await.unwrap();
    assert!(ok);
    let full = repo.get_full_request_by_id("req-a").await.unwrap().unwrap();
    assert_eq!(full.status, "approved");
    assert_eq!(full.signature.as_deref(), Some("sig"));

    let ok = repo.update_request_denied("req-d").await.unwrap();
    assert!(ok);
    let full = repo.get_full_request_by_id("req-d").await.unwrap().unwrap();
    assert_eq!(full.status, "denied");
}

#[tokio::test]
async fn delete_request_removes_row() {
    let repo = super::build_sqlite_test_repo_only().await;

    let row = CreateRequestRow {
        request_id: "req-1".to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[]".to_owned(),
        daemon_public_key: "{\"kty\":\"EC\"}".to_owned(),
        daemon_enc_public_key: "{\"kty\":\"EC\"}".to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: "[]".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    };
    repo.create_request(&row).await.unwrap();

    let deleted = repo.delete_request("req-1").await.unwrap();
    assert!(deleted);
    assert!(repo.get_request_by_id("req-1").await.unwrap().is_none());

    let deleted = repo.delete_request("req-1").await.unwrap();
    assert!(!deleted);
}

#[tokio::test]
async fn add_unavailable_client_id_cas_logic() {
    let repo = super::build_sqlite_test_repo_only().await;

    let row = CreateRequestRow {
        request_id: "req-1".to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[\"c1\",\"c2\"]".to_owned(),
        daemon_public_key: "{\"kty\":\"EC\"}".to_owned(),
        daemon_enc_public_key: "{\"kty\":\"EC\"}".to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: "[]".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    };
    repo.create_request(&row).await.unwrap();

    // Not pending → None
    let result = repo.add_unavailable_client_id("req-1", "c1").await.unwrap();
    assert!(result.is_none());

    repo.update_request_phase2("req-1", "{}").await.unwrap();

    // First add succeeds
    let (updated, client_ids) = repo
        .add_unavailable_client_id("req-1", "c1")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.contains("c1"));
    assert_eq!(client_ids, "[\"c1\",\"c2\"]");

    // Duplicate → None
    let result = repo.add_unavailable_client_id("req-1", "c1").await.unwrap();
    assert!(result.is_none());

    // Second client succeeds
    let (updated, _) = repo
        .add_unavailable_client_id("req-1", "c2")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.contains("c1"));
    assert!(updated.contains("c2"));
}
