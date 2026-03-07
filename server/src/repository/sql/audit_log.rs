use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, Encode, Executor, IntoArguments, Pool, Type};

use super::DbRepository;
use crate::repository::{AuditLogRepository, AuditLogRow};

#[async_trait]
impl<T, DB> AuditLogRepository for T
where
    T: DbRepository<Database = DB> + Send + Sync,
    DB: Database,
    for<'c> &'c Pool<DB>: Executor<'c, Database = DB>,
    for<'q> <DB as Database>::Arguments<'q>: IntoArguments<'q, DB>,
    for<'q> &'q str: Encode<'q, DB> + Type<DB>,
    for<'q> Option<&'q str>: Encode<'q, DB> + Type<DB>,
{
    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (log_id, timestamp, event_type, request_id, request_ip, target_client_ids, responding_client_id, error_code, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(row.log_id.as_str())
        .bind(row.timestamp.as_str())
        .bind(row.event_type.as_str())
        .bind(row.request_id.as_str())
        .bind(row.request_ip.as_deref())
        .bind(row.target_client_ids.as_deref())
        .bind(row.responding_client_id.as_deref())
        .bind(row.error_code.as_deref())
        .bind(row.error_message.as_deref())
        .execute(self.pool())
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
            "DELETE FROM audit_log WHERE (event_type IN ('sign_approved', 'sign_request_created', 'sign_request_dispatched') AND timestamp < $1) OR (event_type IN ('sign_denied', 'sign_device_unavailable', 'sign_unavailable', 'sign_expired', 'sign_cancelled') AND timestamp < $2) OR (event_type = 'sign_result_conflict' AND timestamp < $3)",
        )
        .bind(approved_before)
        .bind(denied_before)
        .bind(conflict_before)
        .execute(self.pool())
        .await
        .context("failed to delete expired audit logs")?;
        Ok(T::rows_affected(&result))
    }
}
