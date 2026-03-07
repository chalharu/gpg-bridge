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

macro_rules! impl_audit_log_repository {
    ($repo_ty:ty) => {
        #[async_trait::async_trait]
        impl crate::repository::AuditLogRepository for $repo_ty {
            async fn create_audit_log(
                &self,
                row: &crate::repository::AuditLogRow,
            ) -> anyhow::Result<()> {
                sqlx::query(
                    "INSERT INTO audit_log (log_id, timestamp, event_type, request_id, request_ip, target_client_ids, responding_client_id, error_code, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind(&row.log_id)
                .bind(&row.timestamp)
                .bind(&row.event_type)
                .bind(&row.request_id)
                .bind(&row.request_ip)
                .bind(&row.target_client_ids)
                .bind(&row.responding_client_id)
                .bind(&row.error_code)
                .bind(&row.error_message)
                .execute(&self.pool)
                .await
                .context("failed to create audit log")?;
                Ok(())
            }

            async fn delete_expired_audit_logs(
                &self,
                approved_before: &str,
                denied_before: &str,
                conflict_before: &str,
            ) -> anyhow::Result<u64> {
                let result = sqlx::query(
                    "DELETE FROM audit_log WHERE \
                     (event_type IN ('sign_approved','sign_request_created','sign_request_dispatched') AND timestamp < $1) \
                     OR (event_type IN ('sign_denied','sign_device_unavailable','sign_unavailable','sign_expired','sign_cancelled') AND timestamp < $2) \
                     OR (event_type = 'sign_result_conflict' AND timestamp < $3)",
                )
                .bind(approved_before)
                .bind(denied_before)
                .bind(conflict_before)
                .execute(&self.pool)
                .await
                .context("failed to delete expired audit logs")?;
                Ok(result.rows_affected())
            }
        }
    };
}

pub(crate) use impl_audit_log_repository;
