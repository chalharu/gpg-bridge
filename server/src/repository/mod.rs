use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use sqlx::{
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::config::{AppConfig, DatabaseKind, detect_database_kind};

mod postgres;
mod sqlite;

pub use postgres::PostgresRepository;
pub use sqlite::SqliteRepository;

pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A row in the `signing_keys` table.
#[derive(Debug, Clone)]
pub struct SigningKeyRow {
    pub kid: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_active: bool,
}

/// A row in the `clients` table.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub client_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub device_token: String,
    pub device_jwt_issued_at: String,
    pub public_keys: String,
    pub default_kid: String,
    pub gpg_keys: String,
}

/// A row in the `pairings` table.
#[derive(Debug, Clone)]
pub struct PairingRow {
    pub pairing_id: String,
    pub expired: String,
    pub client_id: Option<String>,
}

/// A row in the `client_pairings` table.
#[derive(Debug, Clone)]
pub struct ClientPairingRow {
    pub client_id: String,
    pub pairing_id: String,
    pub client_jwt_issued_at: String,
}

/// A row in the `requests` table (subset for auth).
#[derive(Debug, Clone)]
pub struct RequestRow {
    pub request_id: String,
    pub status: String,
    pub daemon_public_key: String,
}

/// Fields required to create a new request row.
#[derive(Debug, Clone)]
pub struct CreateRequestRow {
    pub request_id: String,
    pub status: String,
    pub expired: String,
    pub client_ids: String,
    pub daemon_public_key: String,
    pub daemon_enc_public_key: String,
    pub pairing_ids: String,
    pub e2e_kids: String,
    pub unavailable_client_ids: String,
}

/// A full request row (all columns).
#[derive(Debug, Clone)]
pub struct FullRequestRow {
    pub request_id: String,
    pub status: String,
    pub expired: String,
    pub signature: Option<String>,
    pub client_ids: String,
    pub daemon_public_key: String,
    pub daemon_enc_public_key: String,
    pub pairing_ids: String,
    pub e2e_kids: String,
    pub encrypted_payloads: Option<String>,
    pub unavailable_client_ids: String,
}

/// Fields required to create an audit log entry.
#[derive(Debug, Clone)]
pub struct AuditLogRow {
    pub log_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub request_id: String,
    pub request_ip: Option<String>,
    pub target_client_ids: Option<String>,
    pub responding_client_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[async_trait]
pub trait SignatureRepository: Send + Sync + std::fmt::Debug {
    async fn run_migrations(&self) -> anyhow::Result<()>;
    async fn health_check(&self) -> anyhow::Result<()>;
    fn backend_name(&self) -> &'static str;

    // ---- signing_keys operations ----

    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()>;
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool>;

    /// Delete signing keys whose `expires_at` is before `now`.
    ///
    /// `now` must be an RFC 3339 timestamp with a `+00:00` suffix
    /// (e.g. `"2025-01-01T00:00:00+00:00"`).  The comparison is performed
    /// as a lexicographic string comparison in the database, so a consistent
    /// format is required for correct behaviour.
    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64>;

    // ---- clients operations ----

    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>>;
    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()>;
    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool>;
    async fn client_by_device_token(&self, device_token: &str)
    -> anyhow::Result<Option<ClientRow>>;
    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()>;
    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;

    // ---- client_pairings operations ----

    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>>;

    /// Add a client pairing entry.
    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()>;

    /// Remove a specific client pairing. Returns true if deleted.
    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool>;

    /// Atomically delete a client pairing and, if no pairings remain, delete
    /// the client record.  Returns `(pairing_deleted, client_deleted)`.
    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)>;

    /// Update client_jwt_issued_at for a specific client pairing.
    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool>;

    // ---- pairings operations ----

    /// Create a pairing record (client_id = NULL).
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()>;

    /// Get a pairing record by ID.
    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>>;

    /// Consume a pairing: set client_id only if it is currently NULL.
    /// Returns true if updated (was unconsumed), false if already consumed.
    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool>;

    /// Count unconsumed pairings (client_id IS NULL and not yet expired).
    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64>;

    /// Delete expired pairings.
    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64>;

    // ---- requests operations ----

    async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>>;

    /// Get all columns for a request.
    async fn get_full_request_by_id(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Option<FullRequestRow>>;

    /// CAS update: set status = "pending" and encrypted_payloads only if
    /// status is currently "created".  Returns `true` if updated.
    async fn update_request_phase2(
        &self,
        request_id: &str,
        encrypted_payloads: &str,
    ) -> anyhow::Result<bool>;

    /// Create a new sign request row.
    async fn create_request(&self, row: &CreateRequestRow) -> anyhow::Result<()>;

    /// Count in-flight requests (status IN ('created','pending')) where
    /// `client_ids` contains the given client_id AND `pairing_ids` maps
    /// that client_id to the given pairing_id.
    async fn count_pending_requests_for_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<i64>;

    // ---- audit_log operations ----

    /// Insert an immutable audit-log entry.
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()>;

    // ---- jtis operations ----

    /// Update public_keys and default_kid for a client in one query.
    ///
    /// Uses optimistic locking: the update only succeeds if the current
    /// `updated_at` matches `expected_updated_at`.  Returns `true` if the
    /// row was updated, `false` on a concurrent modification.
    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;

    /// Check if any in-flight request (status=created/pending) references
    /// this kid in `e2e_kids`.
    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool>;

    /// Update gpg_keys for a client.
    ///
    /// Uses optimistic locking: the update only succeeds if the current
    /// `updated_at` matches `expected_updated_at`.  Returns `true` if the
    /// row was updated, `false` on a concurrent modification.
    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;

    /// Store a JTI for replay prevention. Returns `true` if newly inserted,
    /// `false` if the JTI already exists.
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;

    /// Delete JTIs whose `expired` timestamp is before `now`.
    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64>;

    // ---- sign-result operations ----

    /// Get all pending requests where `client_id` is in `client_ids` but
    /// NOT in `unavailable_client_ids`.
    async fn get_pending_requests_for_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>>;

    /// CAS update: status pending → approved, set signature.
    /// Returns `true` if the row was updated.
    async fn update_request_approved(
        &self,
        request_id: &str,
        signature: &str,
    ) -> anyhow::Result<bool>;

    /// CAS update: status pending → denied.
    /// Returns `true` if the row was updated.
    async fn update_request_denied(&self, request_id: &str) -> anyhow::Result<bool>;

    /// Add `client_id` to the `unavailable_client_ids` JSON array (CAS).
    /// Returns `Ok(Some((updated_unavailable_json, client_ids_json)))` if
    /// successfully added, `Ok(None)` if `client_id` was already present
    /// or the request status is not `'pending'`.
    async fn add_unavailable_client_id(
        &self,
        request_id: &str,
        client_id: &str,
    ) -> anyhow::Result<Option<(String, String)>>;

    /// CAS update: status pending → unavailable.
    /// Returns `true` if the row was updated.
    async fn update_request_unavailable(&self, request_id: &str) -> anyhow::Result<bool>;

    /// Delete a request by ID. Returns `true` if a row was deleted.
    async fn delete_request(&self, request_id: &str) -> anyhow::Result<bool>;
}

async fn build_postgres_repository(
    config: &AppConfig,
) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
        .connect(&config.database_url)
        .await
        .context("failed to connect postgres pool")?;

    Ok(Arc::new(PostgresRepository { pool }))
}

async fn build_sqlite_repository(
    config: &AppConfig,
) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    let options = config
        .database_url
        .parse::<SqliteConnectOptions>()
        .context("failed to parse sqlite connection options")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_seconds))
        .connect_with(options)
        .await
        .context("failed to connect sqlite pool")?;

    Ok(Arc::new(SqliteRepository { pool }))
}

pub async fn build_repository(config: &AppConfig) -> anyhow::Result<Arc<dyn SignatureRepository>> {
    match detect_database_kind(&config.database_url)? {
        DatabaseKind::Postgres => build_postgres_repository(config).await,
        DatabaseKind::Sqlite => build_sqlite_repository(config).await,
    }
}
