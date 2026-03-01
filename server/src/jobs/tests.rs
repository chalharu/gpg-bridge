use super::*;
use crate::repository::*;
use async_trait::async_trait;
use std::sync::Mutex;
use tracing_test::traced_test;

// ---- Minimal mock repository ----

#[derive(Debug, Default)]
struct JobMockRepo {
    expired_pairings: Mutex<u64>,
    expired_requests: Mutex<Vec<String>>,
    expired_jtis: Mutex<u64>,
    expired_signing_keys: Mutex<u64>,
    unpaired_clients: Mutex<u64>,
    expired_device_jwt: Mutex<u64>,
    expired_client_jwt: Mutex<u64>,
    expired_audit_logs: Mutex<u64>,
    // Call-tracking fields: record whether each method was called and with what arguments
    called_delete_expired_pairings: Mutex<Vec<String>>,
    called_delete_expired_requests: Mutex<Vec<String>>,
    called_delete_expired_jtis: Mutex<Vec<String>>,
    called_delete_expired_signing_keys: Mutex<Vec<String>>,
    called_delete_unpaired_clients: Mutex<Vec<String>>,
    called_delete_expired_device_jwt_clients: Mutex<Vec<String>>,
    called_delete_expired_client_jwt_pairings: Mutex<Vec<String>>,
    called_delete_expired_audit_logs: Mutex<Vec<(String, String, String)>>,
}

#[async_trait]
impl SignatureRepository for JobMockRepo {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn health_check(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn backend_name(&self) -> &'static str {
        "mock"
    }
    async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        unimplemented!()
    }
    async fn get_signing_key_by_kid(&self, _: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        unimplemented!()
    }
    async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        self.called_delete_expired_signing_keys
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_signing_keys.lock().unwrap())
    }
    async fn get_client_by_id(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
        unimplemented!()
    }
    async fn create_client(&self, _: &ClientRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn client_exists(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn client_by_device_token(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
        unimplemented!()
    }
    async fn update_client_device_token(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, _: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        unimplemented!()
    }
    async fn create_client_pairing(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_client_pairing_and_cleanup(
        &self,
        _: &str,
        _: &str,
    ) -> anyhow::Result<(bool, bool)> {
        unimplemented!()
    }
    async fn update_client_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_pairing(&self, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_pairing_by_id(&self, _: &str) -> anyhow::Result<Option<PairingRow>> {
        unimplemented!()
    }
    async fn consume_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn count_unconsumed_pairings(&self, _: &str) -> anyhow::Result<i64> {
        unimplemented!()
    }
    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        self.called_delete_expired_pairings
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_pairings.lock().unwrap())
    }
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        unimplemented!()
    }
    async fn get_full_request_by_id(&self, _: &str) -> anyhow::Result<Option<FullRequestRow>> {
        unimplemented!()
    }
    async fn update_request_phase2(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_request(&self, _: &CreateRequestRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn count_pending_requests_for_pairing(&self, _: &str, _: &str) -> anyhow::Result<i64> {
        unimplemented!()
    }
    async fn create_audit_log(&self, _: &AuditLogRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_public_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn is_kid_in_flight(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn update_client_gpg_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        self.called_delete_expired_jtis
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_jtis.lock().unwrap())
    }
    async fn get_pending_requests_for_client(
        &self,
        _: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>> {
        unimplemented!()
    }
    async fn update_request_approved(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn update_request_denied(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn add_unavailable_client_id(
        &self,
        _: &str,
        _: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        unimplemented!()
    }
    async fn update_request_unavailable(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_request(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_requests(&self, now: &str) -> anyhow::Result<Vec<String>> {
        self.called_delete_expired_requests
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(self.expired_requests.lock().unwrap().clone())
    }
    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.called_delete_unpaired_clients
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.unpaired_clients.lock().unwrap())
    }
    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.called_delete_expired_device_jwt_clients
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.expired_device_jwt.lock().unwrap())
    }
    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.called_delete_expired_client_jwt_pairings
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.expired_client_jwt.lock().unwrap())
    }
    async fn delete_expired_audit_logs(
        &self,
        approved: &str,
        denied: &str,
        conflict: &str,
    ) -> anyhow::Result<u64> {
        self.called_delete_expired_audit_logs.lock().unwrap().push((
            approved.to_owned(),
            denied.to_owned(),
            conflict.to_owned(),
        ));
        Ok(*self.expired_audit_logs.lock().unwrap())
    }
}

fn test_config() -> CleanupConfig {
    CleanupConfig {
        interval: Duration::from_millis(50),
        unpaired_client_max_age: Duration::from_secs(86400),
        device_jwt_validity: Duration::from_secs(31_536_000),
        client_jwt_validity: Duration::from_secs(31_536_000),
        audit_log_approved_retention: Duration::from_secs(31_536_000),
        audit_log_denied_retention: Duration::from_secs(15_768_000),
        audit_log_conflict_retention: Duration::from_secs(7_884_000),
    }
}

#[tokio::test]
async fn run_all_jobs_calls_cleanup_methods() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let notifier = SignEventNotifier::new();
    let config = test_config();

    run_all_jobs(&repo, &notifier, &config).await;

    assert!(
        !mock
            .called_delete_expired_pairings
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_pairings should have been called",
    );
    assert!(
        !mock
            .called_delete_expired_requests
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_requests should have been called",
    );
    assert!(
        !mock.called_delete_expired_jtis.lock().unwrap().is_empty(),
        "delete_expired_jtis should have been called",
    );
    assert!(
        !mock
            .called_delete_expired_signing_keys
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_signing_keys should have been called",
    );
    assert!(
        !mock
            .called_delete_unpaired_clients
            .lock()
            .unwrap()
            .is_empty(),
        "delete_unpaired_clients should have been called",
    );
    assert!(
        !mock
            .called_delete_expired_device_jwt_clients
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_device_jwt_clients should have been called",
    );
    assert!(
        !mock
            .called_delete_expired_client_jwt_pairings
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_client_jwt_pairings should have been called",
    );
    assert!(
        !mock
            .called_delete_expired_audit_logs
            .lock()
            .unwrap()
            .is_empty(),
        "delete_expired_audit_logs should have been called",
    );
}

#[tokio::test]
async fn expired_requests_trigger_sse_notifications() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_requests: Mutex::new(vec!["req-1".into(), "req-2".into()]),
        ..Default::default()
    });
    let notifier = SignEventNotifier::new();
    let rx1 = notifier.subscribe("req-1");
    let rx2 = notifier.subscribe("req-2");
    let config = test_config();

    run_all_jobs(&repo, &notifier, &config).await;

    let d1 = rx1.borrow().clone().unwrap();
    assert_eq!(d1.status, "expired");
    assert!(d1.signature.is_none());

    let d2 = rx2.borrow().clone().unwrap();
    assert_eq!(d2.status, "expired");
}

#[tokio::test]
async fn cleanup_config_from_app_config() {
    let app = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_CLEANUP_INTERVAL_SECONDS" => Some("120".to_owned()),
        "SERVER_UNPAIRED_CLIENT_MAX_AGE_HOURS" => Some("48".to_owned()),
        _ => None,
    })
    .unwrap();

    let cfg = CleanupConfig::from_app_config(&app);
    assert_eq!(cfg.interval, Duration::from_secs(120));
    assert_eq!(
        cfg.unpaired_client_max_age,
        Duration::from_secs(48 * 60 * 60),
    );
}

#[tokio::test]
async fn cleanup_config_from_app_config_default_unpaired_max_age() {
    let app = AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        _ => None,
    })
    .unwrap();

    let cfg = CleanupConfig::from_app_config(&app);
    assert_eq!(
        cfg.unpaired_client_max_age,
        Duration::from_secs(24 * 60 * 60),
    );
}

#[tokio::test]
async fn spawn_cleanup_scheduler_runs_and_can_be_aborted() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    let notifier = SignEventNotifier::new();
    let config = CleanupConfig {
        interval: Duration::from_millis(10),
        ..test_config()
    };

    let handle = spawn_cleanup_scheduler(repo, notifier, config);

    // Let it run a couple of ticks.
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[traced_test]
async fn run_all_jobs_logs_nonzero_deletions() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_pairings: Mutex::new(3),
        expired_requests: Mutex::new(vec!["r1".into()]),
        expired_jtis: Mutex::new(5),
        expired_signing_keys: Mutex::new(2),
        unpaired_clients: Mutex::new(1),
        expired_device_jwt: Mutex::new(4),
        expired_client_jwt: Mutex::new(7),
        expired_audit_logs: Mutex::new(6),
        ..Default::default()
    });
    let notifier = SignEventNotifier::new();
    let config = test_config();

    run_all_jobs(&repo, &notifier, &config).await;

    assert!(logs_contain("expired pairings cleaned up"));
    assert!(logs_contain(
        "expired requests cleaned up (SSE events sent)"
    ));
    assert!(logs_contain("expired JTIs cleaned up"));
    assert!(logs_contain("expired signing keys cleaned up"));
    assert!(logs_contain("unpaired clients cleaned up"));
    assert!(logs_contain("expired device-JWT clients cleaned up"));
    assert!(logs_contain("expired client-JWT pairings cleaned up"));
    assert!(logs_contain("expired audit logs cleaned up"));
}

// A mock that returns errors for every cleanup method.
#[derive(Debug, Default)]
struct FailingJobMockRepo;

#[async_trait]
impl SignatureRepository for FailingJobMockRepo {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn health_check(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn backend_name(&self) -> &'static str {
        "failing-mock"
    }
    async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        unimplemented!()
    }
    async fn get_signing_key_by_kid(&self, _: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        unimplemented!()
    }
    async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn get_client_by_id(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
        unimplemented!()
    }
    async fn create_client(&self, _: &ClientRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn client_exists(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn client_by_device_token(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
        unimplemented!()
    }
    async fn update_client_device_token(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, _: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        unimplemented!()
    }
    async fn create_client_pairing(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_client_pairing_and_cleanup(
        &self,
        _: &str,
        _: &str,
    ) -> anyhow::Result<(bool, bool)> {
        unimplemented!()
    }
    async fn update_client_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_pairing(&self, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_pairing_by_id(&self, _: &str) -> anyhow::Result<Option<PairingRow>> {
        unimplemented!()
    }
    async fn consume_pairing(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn count_unconsumed_pairings(&self, _: &str) -> anyhow::Result<i64> {
        unimplemented!()
    }
    async fn delete_expired_pairings(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        unimplemented!()
    }
    async fn get_full_request_by_id(&self, _: &str) -> anyhow::Result<Option<FullRequestRow>> {
        unimplemented!()
    }
    async fn update_request_phase2(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn create_request(&self, _: &CreateRequestRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn count_pending_requests_for_pairing(&self, _: &str, _: &str) -> anyhow::Result<i64> {
        unimplemented!()
    }
    async fn create_audit_log(&self, _: &AuditLogRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_public_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn is_kid_in_flight(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn update_client_gpg_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn get_pending_requests_for_client(
        &self,
        _: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>> {
        unimplemented!()
    }
    async fn update_request_approved(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn update_request_denied(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn add_unavailable_client_id(
        &self,
        _: &str,
        _: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        unimplemented!()
    }
    async fn update_request_unavailable(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_request(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_requests(&self, _: &str) -> anyhow::Result<Vec<String>> {
        anyhow::bail!("db error")
    }
    async fn delete_unpaired_clients(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn delete_expired_device_jwt_clients(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn delete_expired_client_jwt_pairings(&self, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
    async fn delete_expired_audit_logs(&self, _: &str, _: &str, _: &str) -> anyhow::Result<u64> {
        anyhow::bail!("db error")
    }
}

#[tokio::test]
#[traced_test]
async fn run_all_jobs_handles_errors_gracefully() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    let notifier = SignEventNotifier::new();
    let config = test_config();

    // Should not panic; all errors are caught and logged.
    run_all_jobs(&repo, &notifier, &config).await;

    assert!(logs_contain("failed to delete expired pairings"));
    assert!(logs_contain("failed to delete expired requests"));
    assert!(logs_contain("failed to delete expired JTIs"));
    assert!(logs_contain("failed to delete expired signing keys"));
    assert!(logs_contain("failed to delete unpaired clients"));
    assert!(logs_contain("failed to delete expired device-JWT clients"));
    assert!(logs_contain("failed to delete expired client-JWT pairings"));
    assert!(logs_contain("failed to delete expired audit logs"));
}

// =========================================================================
// Individual job function tests
// =========================================================================

// --- run_delete_expired_pairings ---

#[tokio::test]
async fn delete_expired_pairings_calls_repo() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_pairings(&repo, "2025-01-01T00:00:00Z").await;
    // If the function body were replaced with `()`, the repo method would
    // never be called and the mock would not record the timestamp.
    let calls = mock.called_delete_expired_pairings.lock().unwrap();
    assert_eq!(*calls, vec!["2025-01-01T00:00:00Z"]);
}

#[tokio::test]
#[traced_test]
async fn delete_expired_pairings_ok_zero_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    run_delete_expired_pairings(&repo, "2025-01-01T00:00:00Z").await;
    assert!(!logs_contain("expired pairings cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_pairings_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_pairings: Mutex::new(5),
        ..Default::default()
    });
    run_delete_expired_pairings(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("expired pairings cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_pairings_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_pairings(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("failed to delete expired pairings"));
}

// --- run_delete_expired_requests ---

#[tokio::test]
async fn delete_expired_requests_calls_repo() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let notifier = SignEventNotifier::new();
    run_delete_expired_requests(&repo, &notifier, "2025-06-01T00:00:00Z").await;
    let calls = mock.called_delete_expired_requests.lock().unwrap();
    assert_eq!(*calls, vec!["2025-06-01T00:00:00Z"]);
}

#[tokio::test]
#[traced_test]
async fn delete_expired_requests_empty_ids_no_sse() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    let notifier = SignEventNotifier::new();
    run_delete_expired_requests(&repo, &notifier, "2025-01-01T00:00:00Z").await;
    assert!(!logs_contain("expired requests cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_requests_sends_sse_for_each_id() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_requests: Mutex::new(vec!["r-a".into(), "r-b".into()]),
        ..Default::default()
    });
    let notifier = SignEventNotifier::new();
    let rx_a = notifier.subscribe("r-a");
    let rx_b = notifier.subscribe("r-b");

    run_delete_expired_requests(&repo, &notifier, "2025-01-01T00:00:00Z").await;

    let data_a = rx_a.borrow().clone().unwrap();
    assert_eq!(data_a.status, "expired");
    assert!(data_a.signature.is_none());

    let data_b = rx_b.borrow().clone().unwrap();
    assert_eq!(data_b.status, "expired");
    assert!(data_b.signature.is_none());
    assert!(logs_contain(
        "expired requests cleaned up (SSE events sent)"
    ));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_requests_single_id_sends_sse() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_requests: Mutex::new(vec!["only-one".into()]),
        ..Default::default()
    });
    let notifier = SignEventNotifier::new();
    let rx = notifier.subscribe("only-one");

    run_delete_expired_requests(&repo, &notifier, "2025-01-01T00:00:00Z").await;

    let data = rx.borrow().clone().unwrap();
    assert_eq!(data.status, "expired");
    assert!(logs_contain(
        "expired requests cleaned up (SSE events sent)"
    ));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_requests_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    let notifier = SignEventNotifier::new();
    run_delete_expired_requests(&repo, &notifier, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("failed to delete expired requests"));
}

// --- run_delete_expired_jtis ---

#[tokio::test]
async fn delete_expired_jtis_calls_repo() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_jtis(&repo, "2025-01-01T00:00:00Z").await;
    let calls = mock.called_delete_expired_jtis.lock().unwrap();
    assert_eq!(*calls, vec!["2025-01-01T00:00:00Z"]);
}

#[tokio::test]
#[traced_test]
async fn delete_expired_jtis_ok_zero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    run_delete_expired_jtis(&repo, "2025-01-01T00:00:00Z").await;
    assert!(!logs_contain("expired JTIs cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_jtis_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_jtis: Mutex::new(10),
        ..Default::default()
    });
    run_delete_expired_jtis(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("expired JTIs cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_jtis_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_jtis(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("failed to delete expired JTIs"));
}

// --- run_delete_expired_signing_keys ---

#[tokio::test]
async fn delete_expired_signing_keys_calls_repo() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_signing_keys(&repo, "2025-01-01T00:00:00Z").await;
    let calls = mock.called_delete_expired_signing_keys.lock().unwrap();
    assert_eq!(*calls, vec!["2025-01-01T00:00:00Z"]);
}

#[tokio::test]
#[traced_test]
async fn delete_expired_signing_keys_ok_zero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    run_delete_expired_signing_keys(&repo, "2025-01-01T00:00:00Z").await;
    assert!(!logs_contain("expired signing keys cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_signing_keys_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_signing_keys: Mutex::new(7),
        ..Default::default()
    });
    run_delete_expired_signing_keys(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("expired signing keys cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_signing_keys_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_signing_keys(&repo, "2025-01-01T00:00:00Z").await;
    assert!(logs_contain("failed to delete expired signing keys"));
}

// --- run_delete_unpaired_clients ---

#[tokio::test]
async fn delete_unpaired_clients_calls_repo_with_cutoff() {
    let now = Utc::now();
    let config = test_config();
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_unpaired_clients(&repo, now, &config).await;
    let calls = mock.called_delete_unpaired_clients.lock().unwrap();
    assert_eq!(calls.len(), 1);
    // Verify the cutoff is a valid RFC3339 timestamp
    chrono::DateTime::parse_from_rfc3339(&calls[0]).expect("valid RFC3339 cutoff");
}

#[tokio::test]
#[traced_test]
async fn delete_unpaired_clients_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        unpaired_clients: Mutex::new(3),
        ..Default::default()
    });
    run_delete_unpaired_clients(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("unpaired clients cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_unpaired_clients_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_unpaired_clients(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("failed to delete unpaired clients"));
}

// --- run_delete_expired_device_jwt_clients ---

#[tokio::test]
async fn delete_expired_device_jwt_clients_calls_repo_with_cutoff() {
    let now = Utc::now();
    let config = test_config();
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_device_jwt_clients(&repo, now, &config).await;
    let calls = mock
        .called_delete_expired_device_jwt_clients
        .lock()
        .unwrap();
    assert_eq!(calls.len(), 1);
    chrono::DateTime::parse_from_rfc3339(&calls[0]).expect("valid RFC3339 cutoff");
}

#[tokio::test]
#[traced_test]
async fn delete_expired_device_jwt_clients_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_device_jwt: Mutex::new(2),
        ..Default::default()
    });
    run_delete_expired_device_jwt_clients(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("expired device-JWT clients cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_device_jwt_clients_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_device_jwt_clients(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("failed to delete expired device-JWT clients"));
}

// --- run_delete_expired_client_jwt_pairings ---

#[tokio::test]
async fn delete_expired_client_jwt_pairings_calls_repo_with_cutoff() {
    let now = Utc::now();
    let config = test_config();
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_client_jwt_pairings(&repo, now, &config).await;
    let calls = mock
        .called_delete_expired_client_jwt_pairings
        .lock()
        .unwrap();
    assert_eq!(calls.len(), 1);
    chrono::DateTime::parse_from_rfc3339(&calls[0]).expect("valid RFC3339 cutoff");
}

#[tokio::test]
#[traced_test]
async fn delete_expired_client_jwt_pairings_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_client_jwt: Mutex::new(4),
        ..Default::default()
    });
    run_delete_expired_client_jwt_pairings(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("expired client-JWT pairings cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_client_jwt_pairings_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_client_jwt_pairings(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("failed to delete expired client-JWT pairings"));
}

// --- run_delete_expired_audit_logs ---

#[tokio::test]
async fn delete_expired_audit_logs_calls_repo_with_three_cutoffs() {
    let now = Utc::now();
    let config = test_config();
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    run_delete_expired_audit_logs(&repo, now, &config).await;
    let calls = mock.called_delete_expired_audit_logs.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (approved, denied, conflict) = &calls[0];
    // All three cutoffs must be valid RFC3339
    chrono::DateTime::parse_from_rfc3339(approved).expect("valid approved cutoff");
    chrono::DateTime::parse_from_rfc3339(denied).expect("valid denied cutoff");
    chrono::DateTime::parse_from_rfc3339(conflict).expect("valid conflict cutoff");
    // The retention durations differ, so cutoffs should differ too:
    // approved (31_536_000s) < denied (15_768_000s) < conflict (7_884_000s)
    // meaning approved cutoff < denied cutoff < conflict cutoff
    assert!(
        approved < denied,
        "approved cutoff should be earlier than denied"
    );
    assert!(
        denied < conflict,
        "denied cutoff should be earlier than conflict"
    );
}

#[tokio::test]
#[traced_test]
async fn delete_expired_audit_logs_ok_nonzero() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_audit_logs: Mutex::new(9),
        ..Default::default()
    });
    run_delete_expired_audit_logs(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("expired audit logs cleaned up"));
}

#[tokio::test]
#[traced_test]
async fn delete_expired_audit_logs_error_does_not_panic() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    run_delete_expired_audit_logs(&repo, Utc::now(), &test_config()).await;
    assert!(logs_contain("failed to delete expired audit logs"));
}

// =========================================================================
// compute_cutoff tests
// =========================================================================

#[test]
fn compute_cutoff_normal_case() {
    let now = Utc::now();
    let dur = Duration::from_secs(3600); // 1 hour
    let result = compute_cutoff(now, dur, "test");
    assert!(result.is_some());
    let cutoff_str = result.unwrap();
    let cutoff = chrono::DateTime::parse_from_rfc3339(&cutoff_str).expect("valid RFC3339");
    // cutoff should be roughly now - 1h
    let expected = now - chrono::Duration::hours(1);
    let diff = (cutoff.timestamp() - expected.timestamp()).abs();
    assert!(diff < 2, "cutoff should be ~1 hour before now");
}

#[test]
fn compute_cutoff_zero_duration() {
    let now = Utc::now();
    let result = compute_cutoff(now, Duration::ZERO, "zero");
    assert!(result.is_some());
    let cutoff = chrono::DateTime::parse_from_rfc3339(&result.unwrap()).expect("valid RFC3339");
    let diff = (cutoff.timestamp() - now.timestamp()).abs();
    assert!(diff < 2);
}

#[test]
fn compute_cutoff_overflow_returns_none() {
    // Use the minimum possible DateTime and a large duration to trigger overflow
    let min_time = chrono::DateTime::<Utc>::MIN_UTC;
    let dur = Duration::from_secs(9_999_999_999);
    let result = compute_cutoff(min_time, dur, "overflow");
    assert!(result.is_none());
}

#[test]
fn compute_cutoff_large_but_valid_duration() {
    let now = Utc::now();
    let dur = Duration::from_secs(365 * 24 * 3600); // 1 year
    let result = compute_cutoff(now, dur, "1year");
    assert!(result.is_some());
    let cutoff_str = result.unwrap();
    chrono::DateTime::parse_from_rfc3339(&cutoff_str).expect("valid RFC3339");
}

// =========================================================================
// Tests for cutoff-based functions with overflow
// =========================================================================

#[tokio::test]
async fn delete_unpaired_clients_overflow_skips_repo_call() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        unpaired_client_max_age: Duration::MAX,
        ..test_config()
    };
    run_delete_unpaired_clients(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock.called_delete_unpaired_clients.lock().unwrap();
    assert!(calls.is_empty(), "repo should not be called on overflow");
}

#[tokio::test]
async fn delete_expired_device_jwt_clients_overflow_skips_repo_call() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        device_jwt_validity: Duration::MAX,
        ..test_config()
    };
    run_delete_expired_device_jwt_clients(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock
        .called_delete_expired_device_jwt_clients
        .lock()
        .unwrap();
    assert!(calls.is_empty(), "repo should not be called on overflow");
}

#[tokio::test]
async fn delete_expired_client_jwt_pairings_overflow_skips_repo_call() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        client_jwt_validity: Duration::MAX,
        ..test_config()
    };
    run_delete_expired_client_jwt_pairings(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock
        .called_delete_expired_client_jwt_pairings
        .lock()
        .unwrap();
    assert!(calls.is_empty(), "repo should not be called on overflow");
}

#[tokio::test]
async fn delete_expired_audit_logs_approved_overflow_skips() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        audit_log_approved_retention: Duration::MAX,
        ..test_config()
    };
    run_delete_expired_audit_logs(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock.called_delete_expired_audit_logs.lock().unwrap();
    assert!(calls.is_empty());
}

#[tokio::test]
async fn delete_expired_audit_logs_denied_overflow_skips() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        audit_log_denied_retention: Duration::MAX,
        ..test_config()
    };
    run_delete_expired_audit_logs(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock.called_delete_expired_audit_logs.lock().unwrap();
    assert!(calls.is_empty());
}

#[tokio::test]
async fn delete_expired_audit_logs_conflict_overflow_skips() {
    let mock = Arc::new(JobMockRepo::default());
    let repo: Arc<dyn SignatureRepository> = mock.clone();
    let config = CleanupConfig {
        audit_log_conflict_retention: Duration::MAX,
        ..test_config()
    };
    run_delete_expired_audit_logs(&repo, chrono::DateTime::<Utc>::MIN_UTC, &config).await;
    let calls = mock.called_delete_expired_audit_logs.lock().unwrap();
    assert!(calls.is_empty());
}
