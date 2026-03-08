//! Shared test infrastructure for the gpg-bridge server crate.
//!
//! Provides a unified [`MockRepository`] that replaces per-module mock
//! implementations, plus common helper functions used across test suites.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::http::AppState;
use crate::http::fcm::{NoopFcmSender, NoopFcmValidator};
use crate::http::pairing::notifier::PairingNotifier;
use crate::http::rate_limit::{SseConnectionTracker, config::SseConnectionConfig};
use crate::http::signing::notifier::SignEventNotifier;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, encrypt_jwe_direct, encrypt_private_key,
    jwk_to_json, sign_jws,
};
use crate::repository::{
    AuditLogRepository, AuditLogRow, CleanupRepository, ClientPairingRepository, ClientPairingRow,
    ClientRepository, ClientRow, CreateRequestRow, FullRequestRow, JtiRepository,
    PairingRepository, PairingRow, RequestRepository, RequestRow, SignatureRepository,
    SigningKeyRepository, SigningKeyRow,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const TEST_SECRET: &str = "test-secret-key!";
pub const BASE_URL: &str = "https://api.example.com";

// ---------------------------------------------------------------------------
// MockRepository
// ---------------------------------------------------------------------------

/// A unified mock repository that supports all test scenarios across the
/// server crate.  Each test configures only the fields it needs; everything
/// else uses sensible defaults provided by [`Default`].
#[derive(Debug)]
pub struct MockRepository {
    // --- Signing Keys ---
    pub signing_key: Option<SigningKeyRow>,
    /// When `Some(x)`, `get_active_signing_key` returns `x` instead of
    /// `signing_key`.  Use `Some(None)` to simulate a missing active key.
    pub active_signing_key_override: Option<Option<SigningKeyRow>>,
    pub signing_key_by_kid_call_count: AtomicUsize,
    pub signing_key_by_kid_max_success: Option<usize>,

    // --- Clients ---
    pub clients: Mutex<Vec<ClientRow>>,

    // --- Client Pairings ---
    pub client_pairings_data: Mutex<Vec<ClientPairingRow>>,

    // --- Pairings ---
    pub pairings: Mutex<Vec<PairingRow>>,

    // --- Requests ---
    pub requests: Mutex<Vec<CreateRequestRow>>,
    pub request: Mutex<Option<RequestRow>>,
    pub full_request: Mutex<Option<FullRequestRow>>,
    pub pending_requests: Mutex<Vec<FullRequestRow>>,
    pub pending_count: i64,

    // --- Audit Logs ---
    pub audit_logs: Mutex<Vec<AuditLogRow>>,

    // --- JTI ---
    pub jti_accepted: bool,

    // --- Pairing Config ---
    pub forced_unconsumed_count: Option<i64>,
    pub force_update_false: bool,

    // --- Device Config ---
    pub in_flight_kids: Mutex<Vec<String>>,
    pub force_gpg_update_conflict: bool,

    // --- Signing Config ---
    pub force_create_request_error: bool,
    pub force_audit_log_error: bool,
    pub update_phase2_result: Mutex<Option<bool>>,
    pub delete_request_result: Mutex<Option<bool>>,

    // --- Sign Result Config ---
    pub approve_result: Mutex<Option<bool>>,
    pub deny_result: Mutex<Option<bool>>,
    pub add_unavailable_result: Mutex<Option<Option<(String, String)>>>,
    pub update_unavailable_result: Mutex<Option<bool>>,

    // --- Error Injection ---
    pub forced_errors: Mutex<HashSet<String>>,

    // --- Job Cleanup: Return Values ---
    pub expired_pairings: Mutex<u64>,
    pub expired_requests: Mutex<Vec<String>>,
    pub expired_jtis: Mutex<u64>,
    pub expired_signing_keys: Mutex<u64>,
    pub unpaired_clients: Mutex<u64>,
    pub expired_device_jwt: Mutex<u64>,
    pub expired_client_jwt: Mutex<u64>,
    pub expired_audit_logs: Mutex<u64>,

    // --- Job Cleanup: Call Tracking ---
    pub called_delete_expired_pairings: Mutex<Vec<String>>,
    pub called_delete_expired_requests: Mutex<Vec<String>>,
    pub called_delete_expired_jtis: Mutex<Vec<String>>,
    pub called_delete_expired_audit_logs: Mutex<Vec<(String, String, String)>>,
    pub called_delete_expired_signing_keys: Mutex<Vec<String>>,
    pub called_delete_unpaired_clients: Mutex<Vec<String>>,
    pub called_delete_expired_device_jwt_clients: Mutex<Vec<String>>,
    pub called_delete_expired_client_jwt_pairings: Mutex<Vec<String>>,

    // --- Health ---
    pub fail_health: bool,
    pub backend: &'static str,
}

impl Default for MockRepository {
    fn default() -> Self {
        Self {
            signing_key: None,
            active_signing_key_override: None,
            signing_key_by_kid_call_count: AtomicUsize::new(0),
            signing_key_by_kid_max_success: None,
            clients: Mutex::new(Vec::new()),
            client_pairings_data: Mutex::new(Vec::new()),
            pairings: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            request: Mutex::new(None),
            full_request: Mutex::new(None),
            pending_requests: Mutex::new(Vec::new()),
            pending_count: 0,
            audit_logs: Mutex::new(Vec::new()),
            jti_accepted: true,
            forced_unconsumed_count: None,
            force_update_false: false,
            in_flight_kids: Mutex::new(Vec::new()),
            force_gpg_update_conflict: false,
            force_create_request_error: false,
            force_audit_log_error: false,
            update_phase2_result: Mutex::new(None),
            delete_request_result: Mutex::new(None),
            approve_result: Mutex::new(None),
            deny_result: Mutex::new(None),
            add_unavailable_result: Mutex::new(None),
            update_unavailable_result: Mutex::new(None),
            forced_errors: Mutex::new(HashSet::new()),
            expired_pairings: Mutex::new(0),
            expired_requests: Mutex::new(Vec::new()),
            expired_jtis: Mutex::new(0),
            expired_signing_keys: Mutex::new(0),
            unpaired_clients: Mutex::new(0),
            expired_device_jwt: Mutex::new(0),
            expired_client_jwt: Mutex::new(0),
            expired_audit_logs: Mutex::new(0),
            called_delete_expired_pairings: Mutex::new(Vec::new()),
            called_delete_expired_requests: Mutex::new(Vec::new()),
            called_delete_expired_jtis: Mutex::new(Vec::new()),
            called_delete_expired_audit_logs: Mutex::new(Vec::new()),
            called_delete_expired_signing_keys: Mutex::new(Vec::new()),
            called_delete_unpaired_clients: Mutex::new(Vec::new()),
            called_delete_expired_device_jwt_clients: Mutex::new(Vec::new()),
            called_delete_expired_client_jwt_pairings: Mutex::new(Vec::new()),
            fail_health: false,
            backend: "mock",
        }
    }
}

impl MockRepository {
    /// Create a mock with a signing key pre-configured.
    pub fn new(signing_key: SigningKeyRow) -> Self {
        Self {
            signing_key: Some(signing_key),
            ..Default::default()
        }
    }

    /// Create a mock with a signing key and one initial client.
    pub fn with_client(signing_key: SigningKeyRow, client: ClientRow) -> Self {
        Self {
            signing_key: Some(signing_key),
            clients: Mutex::new(vec![client]),
            ..Default::default()
        }
    }

    /// Register a forced error for a specific method name.
    pub fn force_error(&self, method: &str) {
        self.forced_errors.lock().unwrap().insert(method.to_owned());
    }

    /// Check whether a forced error is registered for the given method.
    fn check_forced_error(&self, method: &str) -> anyhow::Result<()> {
        if self.forced_errors.lock().unwrap().contains(method) {
            anyhow::bail!("forced test error for {method}");
        }
        Ok(())
    }
}

#[async_trait]
impl SigningKeyRepository for MockRepository {
    async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        self.check_forced_error("get_active_signing_key")?;
        if let Some(ref override_val) = self.active_signing_key_override {
            return Ok(override_val.clone());
        }
        Ok(self.signing_key.clone())
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        self.check_forced_error("get_signing_key_by_kid")?;
        if let Some(max) = self.signing_key_by_kid_max_success {
            let count = self
                .signing_key_by_kid_call_count
                .fetch_add(1, Ordering::SeqCst);
            if count >= max {
                return Ok(None);
            }
        }
        Ok(self.signing_key.as_ref().filter(|k| k.kid == kid).cloned())
    }

    async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_signing_keys")?;
        self.called_delete_expired_signing_keys
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_signing_keys.lock().unwrap())
    }
}

#[async_trait]
impl ClientRepository for MockRepository {
    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
    }

    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        self.clients.lock().unwrap().push(row.clone());
        Ok(())
    }

    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.client_id == client_id))
    }

    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.device_token == device_token)
            .cloned())
    }

    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.device_token = device_token.to_owned();
        }
        Ok(())
    }

    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.default_kid = default_kid.to_owned();
        }
        Ok(())
    }

    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        self.clients
            .lock()
            .unwrap()
            .retain(|c| c.client_id != client_id);
        Ok(())
    }

    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        _updated_at: &str,
    ) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.iter_mut().find(|c| c.client_id == client_id) {
            c.device_jwt_issued_at = issued_at.to_owned();
        }
        Ok(())
    }

    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients
            .iter_mut()
            .find(|c| c.client_id == client_id && c.updated_at == expected_updated_at)
        {
            c.public_keys = public_keys.to_owned();
            c.default_kid = default_kid.to_owned();
            c.updated_at = updated_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        if self.force_gpg_update_conflict {
            return Ok(false);
        }
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients
            .iter_mut()
            .find(|c| c.client_id == client_id && c.updated_at == expected_updated_at)
        {
            c.gpg_keys = gpg_keys.to_owned();
            c.updated_at = updated_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl ClientPairingRepository for MockRepository {
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        self.check_forced_error("get_client_pairings")?;
        Ok(self
            .client_pairings_data
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.client_id == client_id)
            .cloned()
            .collect())
    }

    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        self.check_forced_error("create_client_pairing")?;
        self.client_pairings_data
            .lock()
            .unwrap()
            .push(ClientPairingRow {
                client_id: client_id.to_owned(),
                pairing_id: pairing_id.to_owned(),
                client_jwt_issued_at: client_jwt_issued_at.to_owned(),
            });
        Ok(())
    }

    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let mut cp = self.client_pairings_data.lock().unwrap();
        let before = cp.len();
        cp.retain(|p| !(p.client_id == client_id && p.pairing_id == pairing_id));
        Ok(cp.len() < before)
    }

    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        self.check_forced_error("delete_client_pairing_and_cleanup")?;
        let mut cp = self.client_pairings_data.lock().unwrap();
        let before = cp.len();
        cp.retain(|p| !(p.client_id == client_id && p.pairing_id == pairing_id));
        let pairing_deleted = cp.len() < before;
        let mut client_deleted = false;
        if pairing_deleted && !cp.iter().any(|p| p.client_id == client_id) {
            drop(cp);
            self.clients
                .lock()
                .unwrap()
                .retain(|c| c.client_id != client_id);
            client_deleted = true;
        }
        Ok((pairing_deleted, client_deleted))
    }

    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        self.check_forced_error("update_client_jwt_issued_at")?;
        if self.force_update_false {
            return Ok(false);
        }
        let mut cp = self.client_pairings_data.lock().unwrap();
        if let Some(p) = cp
            .iter_mut()
            .find(|p| p.client_id == client_id && p.pairing_id == pairing_id)
        {
            p.client_jwt_issued_at = issued_at.to_owned();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl PairingRepository for MockRepository {
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        self.check_forced_error("create_pairing")?;
        self.pairings.lock().unwrap().push(PairingRow {
            pairing_id: pairing_id.to_owned(),
            expired: expired.to_owned(),
            client_id: None,
        });
        Ok(())
    }

    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        self.check_forced_error("get_pairing_by_id")?;
        Ok(self
            .pairings
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.pairing_id == pairing_id)
            .cloned())
    }

    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        self.check_forced_error("consume_pairing")?;
        let mut pairings = self.pairings.lock().unwrap();
        if let Some(p) = pairings
            .iter_mut()
            .find(|p| p.pairing_id == pairing_id && p.client_id.is_none())
        {
            p.client_id = Some(client_id.to_owned());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn count_unconsumed_pairings(&self, _now: &str) -> anyhow::Result<i64> {
        self.check_forced_error("count_unconsumed_pairings")?;
        if let Some(count) = self.forced_unconsumed_count {
            return Ok(count);
        }
        let pairings = self.pairings.lock().unwrap();
        Ok(pairings.iter().filter(|p| p.client_id.is_none()).count() as i64)
    }

    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_pairings")?;
        self.called_delete_expired_pairings
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_pairings.lock().unwrap())
    }
}

#[async_trait]
impl RequestRepository for MockRepository {
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(self.request.lock().unwrap().clone())
    }

    async fn get_full_request_by_id(
        &self,
        _request_id: &str,
    ) -> anyhow::Result<Option<FullRequestRow>> {
        Ok(self.full_request.lock().unwrap().clone())
    }

    async fn update_request_phase2(
        &self,
        _request_id: &str,
        _encrypted_payloads: &str,
    ) -> anyhow::Result<bool> {
        Ok(self.update_phase2_result.lock().unwrap().unwrap_or(true))
    }

    async fn create_request(&self, row: &CreateRequestRow) -> anyhow::Result<()> {
        self.check_forced_error("create_request")?;
        if self.force_create_request_error {
            anyhow::bail!("forced create_request error");
        }
        self.requests.lock().unwrap().push(row.clone());
        Ok(())
    }

    async fn count_pending_requests_for_pairing(
        &self,
        _client_id: &str,
        _pairing_id: &str,
    ) -> anyhow::Result<i64> {
        Ok(self.pending_count)
    }

    async fn get_pending_requests_for_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>> {
        Ok(self
            .pending_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                let cids: Vec<String> = serde_json::from_str(&r.client_ids).unwrap_or_default();
                cids.contains(&client_id.to_owned())
            })
            .cloned()
            .collect())
    }

    async fn update_request_approved(
        &self,
        _request_id: &str,
        _signature: &str,
    ) -> anyhow::Result<bool> {
        Ok(self.approve_result.lock().unwrap().unwrap_or(true))
    }

    async fn update_request_denied(&self, _request_id: &str) -> anyhow::Result<bool> {
        Ok(self.deny_result.lock().unwrap().unwrap_or(true))
    }

    async fn add_unavailable_client_id(
        &self,
        _request_id: &str,
        _client_id: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        Ok(self
            .add_unavailable_result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Some(("[]".into(), "[]".into()))))
    }

    async fn update_request_unavailable(&self, _request_id: &str) -> anyhow::Result<bool> {
        Ok(self
            .update_unavailable_result
            .lock()
            .unwrap()
            .unwrap_or(true))
    }

    async fn delete_request(&self, _request_id: &str) -> anyhow::Result<bool> {
        Ok(self.delete_request_result.lock().unwrap().unwrap_or(true))
    }

    async fn delete_expired_requests(&self, now: &str) -> anyhow::Result<Vec<String>> {
        self.check_forced_error("delete_expired_requests")?;
        self.called_delete_expired_requests
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(self.expired_requests.lock().unwrap().clone())
    }

    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool> {
        Ok(self.in_flight_kids.lock().unwrap().iter().any(|k| k == kid))
    }
}

#[async_trait]
impl AuditLogRepository for MockRepository {
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()> {
        if self.force_audit_log_error {
            anyhow::bail!("forced audit_log error");
        }
        self.audit_logs.lock().unwrap().push(row.clone());
        Ok(())
    }

    async fn delete_expired_audit_logs(
        &self,
        approved: &str,
        denied: &str,
        conflict: &str,
    ) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_audit_logs")?;
        self.called_delete_expired_audit_logs.lock().unwrap().push((
            approved.to_owned(),
            denied.to_owned(),
            conflict.to_owned(),
        ));
        Ok(*self.expired_audit_logs.lock().unwrap())
    }
}

#[async_trait]
impl JtiRepository for MockRepository {
    async fn store_jti(&self, _jti: &str, _expired: &str) -> anyhow::Result<bool> {
        Ok(self.jti_accepted)
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_jtis")?;
        self.called_delete_expired_jtis
            .lock()
            .unwrap()
            .push(now.to_owned());
        Ok(*self.expired_jtis.lock().unwrap())
    }
}

#[async_trait]
impl CleanupRepository for MockRepository {
    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_unpaired_clients")?;
        self.called_delete_unpaired_clients
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.unpaired_clients.lock().unwrap())
    }

    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_device_jwt_clients")?;
        self.called_delete_expired_device_jwt_clients
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.expired_device_jwt.lock().unwrap())
    }

    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.check_forced_error("delete_expired_client_jwt_pairings")?;
        self.called_delete_expired_client_jwt_pairings
            .lock()
            .unwrap()
            .push(cutoff.to_owned());
        Ok(*self.expired_client_jwt.lock().unwrap())
    }
}

#[async_trait]
impl SignatureRepository for MockRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        if self.fail_health {
            anyhow::bail!("connection refused");
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        self.backend
    }
}

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

/// Build a [`SigningKeyRow`] from a key pair, encrypting the private key with
/// [`TEST_SECRET`].
pub fn make_signing_key_row(
    priv_jwk: &josekit::jwk::Jwk,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
) -> SigningKeyRow {
    let private_json = jwk_to_json(priv_jwk).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    SigningKeyRow {
        kid: kid.to_owned(),
        private_key: encrypted,
        public_key: jwk_to_json(pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        expires_at: "2027-01-01T00:00:00Z".to_owned(),
        is_active: true,
    }
}

/// Build a client JWT (outer JWS wrapping an inner JWE) suitable for pairing
/// and signing endpoints.
pub fn make_client_jwt(
    priv_jwk: &josekit::jwk::Jwk,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
    client_id: &str,
    pairing_id: &str,
) -> String {
    let inner = ClientInnerClaims {
        sub: client_id.into(),
        pairing_id: pairing_id.into(),
    };
    let inner_bytes = serde_json::to_vec(&inner).unwrap();
    let jwe = encrypt_jwe_direct(&inner_bytes, pub_jwk).unwrap();
    let outer = ClientOuterClaims {
        payload_type: PayloadType::Client,
        client_jwe: jwe,
        exp: 1_900_000_000,
    };
    sign_jws(&outer, priv_jwk, kid).unwrap()
}

/// Decode a JSON response body for HTTP handler tests.
pub async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Build an in-memory [`SqliteRepository`] with migrations applied, wrapped
/// in `Arc` for use in HTTP handler tests.
pub async fn build_test_sqlite_repo() -> Arc<crate::repository::SqliteRepository> {
    use crate::repository::MIGRATOR;
    use crate::repository::sqlite::tests::build_sqlite_test_pool;

    let pool = build_sqlite_test_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    Arc::new(crate::repository::SqliteRepository { pool })
}

/// Build an [`AppState`] from any [`SignatureRepository`] implementor, using
/// standard test defaults.
pub fn make_test_app_state(repo: impl SignatureRepository + 'static) -> AppState {
    make_test_app_state_arc(Arc::new(repo))
}

/// Build an [`AppState`] from an `Arc<dyn SignatureRepository>`.
pub fn make_test_app_state_arc(repository: Arc<dyn SignatureRepository>) -> AppState {
    AppState {
        repository,
        base_url: BASE_URL.to_owned(),
        signing_key_secret: TEST_SECRET.to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_validator: Arc::new(NoopFcmValidator),
        fcm_sender: Arc::new(NoopFcmSender),
        sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: SignEventNotifier::new(),
    }
}
