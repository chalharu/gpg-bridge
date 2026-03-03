use async_trait::async_trait;

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
pub trait AuditLogRepository: Send + Sync {
    /// Insert an immutable audit-log entry.
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()>;

    /// Delete audit logs older than the given retention cutoffs.
    ///
    /// Each parameter is an RFC 3339 timestamp.  Rows are deleted when:
    /// - `sign_approved`, `sign_request_created`, `sign_request_dispatched`
    ///    have `timestamp < approved_before` (1-year retention)
    /// - `sign_denied`, `sign_device_unavailable`, `sign_unavailable`,
    ///    `sign_expired`, `sign_cancelled`
    ///    have `timestamp < denied_before` (6-month retention)
    /// - `sign_result_conflict`
    ///    has `timestamp < conflict_before` (3-month retention)
    async fn delete_expired_audit_logs(
        &self,
        approved_before: &str,
        denied_before: &str,
        conflict_before: &str,
    ) -> anyhow::Result<u64>;
}
