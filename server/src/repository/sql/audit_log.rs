use anyhow::Context;
use async_trait::async_trait;

use crate::repository::{AuditLogRepository, AuditLogRow};

#[async_trait]
trait CommonAuditLogRepository: Send + Sync {
    async fn create_audit_log_common(&self, row: &AuditLogRow) -> anyhow::Result<()>;
    async fn delete_expired_audit_logs_common(
        &self,
        approved_before: &str,
        denied_before: &str,
        conflict_before: &str,
    ) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> AuditLogRepository for T
where
    T: CommonAuditLogRepository + Send + Sync,
{
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()> {
        self.create_audit_log_common(row).await
    }

    async fn delete_expired_audit_logs(
        &self,
        approved_before: &str,
        denied_before: &str,
        conflict_before: &str,
    ) -> anyhow::Result<u64> {
        self.delete_expired_audit_logs_common(approved_before, denied_before, conflict_before)
            .await
    }
}

impl_for_sql_backends!(CommonAuditLogRepository {
    async fn create_audit_log_common(&self, row: &AuditLogRow) -> anyhow::Result<()> {
        execute_query!(
            "INSERT INTO audit_log (log_id, timestamp, event_type, request_id, request_ip, target_client_ids, responding_client_id, error_code, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &self.pool,
            "failed to create audit log",
            &row.log_id,
            &row.timestamp,
            &row.event_type,
            &row.request_id,
            &row.request_ip,
            &row.target_client_ids,
            &row.responding_client_id,
            &row.error_code,
            &row.error_message,
        )?;
        Ok(())
    }

    async fn delete_expired_audit_logs_common(
        &self,
        approved_before: &str,
        denied_before: &str,
        conflict_before: &str,
    ) -> anyhow::Result<u64> {
        let result = execute_query!(
            "DELETE FROM audit_log WHERE \
             (event_type IN ('sign_approved','sign_request_created','sign_request_dispatched') AND timestamp < $1) \
             OR (event_type IN ('sign_denied','sign_device_unavailable','sign_unavailable','sign_expired','sign_cancelled') AND timestamp < $2) \
             OR (event_type = 'sign_result_conflict' AND timestamp < $3)",
            &self.pool,
            "failed to delete expired audit logs",
            approved_before,
            denied_before,
            conflict_before,
        )?;
        Ok(result.rows_affected())
    }
});
