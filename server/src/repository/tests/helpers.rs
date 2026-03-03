use crate::repository::{AuditLogRow, ClientRow, CreateRequestRow, SignatureRepository};

/// Insert a minimal test client using the `ClientRepository` trait.
pub(crate) async fn insert_test_client(
    repo: &dyn SignatureRepository,
    client_id: &str,
    public_keys: &str,
) {
    repo.create_client(&ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        updated_at: "2026-01-01T00:00:00Z".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00Z".to_owned(),
        public_keys: public_keys.to_owned(),
        default_kid: "kid-1".to_owned(),
        gpg_keys: "[]".to_owned(),
    })
    .await
    .unwrap();
}

/// Insert a minimal test request (status = "created", far-future expiry).
pub(crate) async fn insert_test_request(repo: &dyn SignatureRepository, request_id: &str) {
    repo.create_request(&CreateRequestRow {
        request_id: request_id.to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[]".to_owned(),
        daemon_public_key: r#"{"kty":"EC"}"#.to_owned(),
        daemon_enc_public_key: r#"{"kty":"EC"}"#.to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: "{}".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    })
    .await
    .unwrap();
}

/// Insert a request and transition it to the desired `status` through the
/// proper state machine (create → phase2 → approve/deny).
pub(crate) async fn insert_request_with_status(
    repo: &dyn SignatureRepository,
    request_id: &str,
    status: &str,
    expired: &str,
) {
    repo.create_request(&CreateRequestRow {
        request_id: request_id.to_owned(),
        status: "created".to_owned(),
        expired: expired.to_owned(),
        client_ids: "[]".to_owned(),
        daemon_public_key: r#"{"kty":"EC"}"#.to_owned(),
        daemon_enc_public_key: r#"{"kty":"EC"}"#.to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: "{}".to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    })
    .await
    .unwrap();

    transition_request(repo, request_id, status).await;
}

/// Insert a request with specific `e2e_kids` and transition to `status`.
pub(crate) async fn insert_request_with_e2e_kids(
    repo: &dyn SignatureRepository,
    request_id: &str,
    status: &str,
    e2e_kids: &str,
) {
    repo.create_request(&CreateRequestRow {
        request_id: request_id.to_owned(),
        status: "created".to_owned(),
        expired: "2027-01-01T00:00:00Z".to_owned(),
        client_ids: "[]".to_owned(),
        daemon_public_key: r#"{"kty":"EC"}"#.to_owned(),
        daemon_enc_public_key: r#"{"kty":"EC"}"#.to_owned(),
        pairing_ids: "{}".to_owned(),
        e2e_kids: e2e_kids.to_owned(),
        unavailable_client_ids: "[]".to_owned(),
    })
    .await
    .unwrap();

    transition_request(repo, request_id, status).await;
}

/// Transition a request that is currently "created" to the target status.
async fn transition_request(repo: &dyn SignatureRepository, request_id: &str, target_status: &str) {
    match target_status {
        "created" => {}
        "pending" => {
            repo.update_request_phase2(request_id, "{}").await.unwrap();
        }
        "approved" => {
            repo.update_request_phase2(request_id, "{}").await.unwrap();
            repo.update_request_approved(request_id, "sig")
                .await
                .unwrap();
        }
        "denied" => {
            repo.update_request_phase2(request_id, "{}").await.unwrap();
            repo.update_request_denied(request_id).await.unwrap();
        }
        _ => panic!("unsupported target status: {target_status}"),
    }
}

/// Insert an audit-log entry using the `AuditLogRepository` trait.
pub(crate) async fn insert_audit_log(
    repo: &dyn SignatureRepository,
    log_id: &str,
    event_type: &str,
    timestamp: &str,
) {
    repo.create_audit_log(&AuditLogRow {
        log_id: log_id.to_owned(),
        timestamp: timestamp.to_owned(),
        event_type: event_type.to_owned(),
        request_id: "req-1".to_owned(),
        request_ip: None,
        target_client_ids: None,
        responding_client_id: None,
        error_code: None,
        error_message: None,
    })
    .await
    .unwrap();
}
