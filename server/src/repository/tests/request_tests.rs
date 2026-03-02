use crate::repository::CreateRequestRow;

use super::fixture::TestFixture;
use super::helpers;
use super::repo_test;

async fn get_request_by_id_found(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_test_request(repo, "req-1").await;
    let request = repo.get_request_by_id("req-1").await.unwrap().unwrap();
    assert_eq!(request.request_id, "req-1");
    assert_eq!(request.status, "created");
}
repo_test!(get_request_by_id_found);

async fn get_request_by_id_not_found(f: &dyn TestFixture) {
    let repo = f.repo();

    assert!(
        repo.get_request_by_id("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}
repo_test!(get_request_by_id_not_found);

async fn delete_expired_requests_returns_incomplete_ids(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_request_with_status(repo, "r-created", "created", "2025-01-01T00:00:00Z").await;
    helpers::insert_request_with_status(repo, "r-pending", "pending", "2025-01-01T00:00:00Z").await;
    helpers::insert_request_with_status(repo, "r-approved", "approved", "2025-01-01T00:00:00Z")
        .await;
    helpers::insert_request_with_status(repo, "r-future", "created", "2027-01-01T00:00:00Z").await;

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
repo_test!(delete_expired_requests_returns_incomplete_ids);

async fn delete_expired_requests_empty_when_none(f: &dyn TestFixture) {
    let repo = f.repo();

    let ids = repo
        .delete_expired_requests("2026-01-01T00:00:00Z")
        .await
        .unwrap();
    assert!(ids.is_empty());
}
repo_test!(delete_expired_requests_empty_when_none);

async fn is_kid_in_flight_returns_true_when_request_has_matching_kid(f: &dyn TestFixture) {
    let repo = f.repo();

    helpers::insert_request_with_e2e_kids(repo, "req-1", "created", r#"["kid-test","kid-other"]"#)
        .await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}
repo_test!(is_kid_in_flight_returns_true_when_request_has_matching_kid);

async fn is_kid_in_flight_returns_false_when_no_matching_request(f: &dyn TestFixture) {
    let repo = f.repo();

    // No requests at all
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // Request exists but with a different kid
    helpers::insert_request_with_e2e_kids(repo, "req-1", "created", r#"["kid-other"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());
}
repo_test!(is_kid_in_flight_returns_false_when_no_matching_request);

async fn is_kid_in_flight_ignores_non_active_statuses(f: &dyn TestFixture) {
    let repo = f.repo();

    // approved request should NOT count
    helpers::insert_request_with_e2e_kids(repo, "req-1", "approved", r#"["kid-test"]"#).await;
    assert!(!repo.is_kid_in_flight("kid-test").await.unwrap());

    // pending request SHOULD count
    helpers::insert_request_with_e2e_kids(repo, "req-2", "pending", r#"["kid-test"]"#).await;
    assert!(repo.is_kid_in_flight("kid-test").await.unwrap());
}
repo_test!(is_kid_in_flight_ignores_non_active_statuses);

async fn create_request_and_get_full(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(create_request_and_get_full);

async fn update_request_phase2_cas(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(update_request_phase2_cas);

async fn update_request_approved_and_denied_cas(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(update_request_approved_and_denied_cas);

async fn delete_request_removes_row(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(delete_request_removes_row);

async fn add_unavailable_client_id_cas_logic(f: &dyn TestFixture) {
    let repo = f.repo();

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
repo_test!(add_unavailable_client_id_cas_logic);
