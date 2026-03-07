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

#[async_trait]
impl CommonAuditLogRepository for crate::repository::PostgresRepository {
    async fn create_audit_log_common(&self, row: &AuditLogRow) -> anyhow::Result<()> {
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

    async fn delete_expired_audit_logs_common(
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

#[async_trait]
impl CommonAuditLogRepository for crate::repository::SqliteRepository {
    async fn create_audit_log_common(&self, row: &AuditLogRow) -> anyhow::Result<()> {
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

    async fn delete_expired_audit_logs_common(
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
