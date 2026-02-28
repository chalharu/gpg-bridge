use super::*;
use crate::repository::*;
use async_trait::async_trait;
use std::sync::Mutex;

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
    async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
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
    async fn delete_expired_pairings(&self, _: &str) -> anyhow::Result<u64> {
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
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
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
    async fn delete_expired_requests(&self, _: &str) -> anyhow::Result<Vec<String>> {
        Ok(self.expired_requests.lock().unwrap().clone())
    }
    async fn delete_unpaired_clients(&self, _: &str) -> anyhow::Result<u64> {
        Ok(*self.unpaired_clients.lock().unwrap())
    }
    async fn delete_expired_device_jwt_clients(&self, _: &str) -> anyhow::Result<u64> {
        Ok(*self.expired_device_jwt.lock().unwrap())
    }
    async fn delete_expired_client_jwt_pairings(&self, _: &str) -> anyhow::Result<u64> {
        Ok(*self.expired_client_jwt.lock().unwrap())
    }
}

fn test_config() -> CleanupConfig {
    CleanupConfig {
        interval: Duration::from_millis(50),
        unpaired_client_max_age: Duration::from_secs(86400),
        device_jwt_validity: Duration::from_secs(31_536_000),
        client_jwt_validity: Duration::from_secs(31_536_000),
    }
}

#[tokio::test]
async fn run_all_jobs_calls_cleanup_methods() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo::default());
    let notifier = SignEventNotifier::new();
    let config = test_config();

    run_all_jobs(&repo, &notifier, &config).await;
    // Should complete without panic (all return 0 / empty).
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
async fn run_all_jobs_logs_nonzero_deletions() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(JobMockRepo {
        expired_pairings: Mutex::new(3),
        expired_requests: Mutex::new(vec!["r1".into()]),
        expired_jtis: Mutex::new(5),
        expired_signing_keys: Mutex::new(2),
        unpaired_clients: Mutex::new(1),
        expired_device_jwt: Mutex::new(4),
        expired_client_jwt: Mutex::new(7),
    });
    let notifier = SignEventNotifier::new();
    let config = test_config();

    // All branches with n > 0 are exercised.
    run_all_jobs(&repo, &notifier, &config).await;
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
}

#[tokio::test]
async fn run_all_jobs_handles_errors_gracefully() {
    let repo: Arc<dyn SignatureRepository> = Arc::new(FailingJobMockRepo);
    let notifier = SignEventNotifier::new();
    let config = test_config();

    // Should not panic; all errors are caught and logged.
    run_all_jobs(&repo, &notifier, &config).await;
}
