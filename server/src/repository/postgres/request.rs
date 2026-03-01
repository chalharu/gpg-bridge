use anyhow::Context;
use async_trait::async_trait;

use super::PostgresRepository;
use crate::repository::request::try_append_unavailable;
use crate::repository::{CreateRequestRow, FullRequestRow, RequestRepository, RequestRow};

#[async_trait]
impl RequestRepository for PostgresRepository {
    async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>> {
        let row = sqlx::query_as::<_, PgRequestRow>(
            "SELECT request_id, status, daemon_public_key FROM requests WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get request by id")?;
        Ok(row.map(Into::into))
    }

    async fn get_full_request_by_id(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Option<FullRequestRow>> {
        let row = sqlx::query_as::<_, PgFullRequestRow>(
            "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get full request by id")?;
        Ok(row.map(Into::into))
    }

    async fn update_request_phase2(
        &self,
        request_id: &str,
        encrypted_payloads: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE requests SET status = 'pending', encrypted_payloads = $1 WHERE request_id = $2 AND status = 'created'",
        )
        .bind(encrypted_payloads)
        .bind(request_id)
        .execute(&self.pool)
        .await
        .context("failed to update request phase2")?;
        Ok(result.rows_affected() > 0)
    }

    async fn create_request(&self, row: &CreateRequestRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, unavailable_client_ids) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&row.request_id)
        .bind(&row.status)
        .bind(&row.expired)
        .bind(&row.client_ids)
        .bind(&row.daemon_public_key)
        .bind(&row.daemon_enc_public_key)
        .bind(&row.pairing_ids)
        .bind(&row.e2e_kids)
        .bind(&row.unavailable_client_ids)
        .execute(&self.pool)
        .await
        .context("failed to create request")?;
        Ok(())
    }

    async fn count_pending_requests_for_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM requests WHERE status IN ('created', 'pending') AND client_ids::jsonb ? $1 AND pairing_ids::jsonb ->> $1 = $2",
        )
        .bind(client_id)
        .bind(pairing_id)
        .fetch_one(&self.pool)
        .await
        .context("failed to count pending requests for pairing")?;
        Ok(count)
    }

    async fn get_pending_requests_for_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>> {
        let rows = sqlx::query_as::<_, PgFullRequestRow>(
            "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE status = 'pending' AND expired > NOW() AND client_ids::jsonb ? $1 AND NOT (unavailable_client_ids::jsonb ? $1)",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get pending requests for client")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_request_approved(
        &self,
        request_id: &str,
        signature: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE requests SET status = 'approved', signature = $1 WHERE request_id = $2 AND status = 'pending'",
        )
        .bind(signature)
        .bind(request_id)
        .execute(&self.pool)
        .await
        .context("failed to update request approved")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_request_denied(&self, request_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE requests SET status = 'denied' WHERE request_id = $1 AND status = 'pending'",
        )
        .bind(request_id)
        .execute(&self.pool)
        .await
        .context("failed to update request denied")?;
        Ok(result.rows_affected() > 0)
    }

    async fn add_unavailable_client_id(
        &self,
        request_id: &str,
        client_id: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;

        let row = sqlx::query_as::<_, (String, String, String)>(
            "SELECT unavailable_client_ids, client_ids, status FROM requests WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .context("failed to read request for unavailable update")?;

        let (updated, client_ids) = match try_append_unavailable(row, client_id)? {
            Some(v) => v,
            None => return Ok(None),
        };

        sqlx::query(
            "UPDATE requests SET unavailable_client_ids = $1 WHERE request_id = $2 AND status = 'pending'",
        )
        .bind(&updated)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .context("failed to update unavailable_client_ids")?;

        tx.commit().await.context("failed to commit transaction")?;

        Ok(Some((updated, client_ids)))
    }

    async fn update_request_unavailable(&self, request_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE requests SET status = 'unavailable' WHERE request_id = $1 AND status = 'pending'",
        )
        .bind(request_id)
        .execute(&self.pool)
        .await
        .context("failed to update request unavailable")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_request(&self, request_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM requests WHERE request_id = $1")
            .bind(request_id)
            .execute(&self.pool)
            .await
            .context("failed to delete request")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_requests(&self, now: &str) -> anyhow::Result<Vec<String>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;

        let incomplete = sqlx::query_scalar::<_, String>(
            "SELECT request_id FROM requests WHERE expired < $1 AND status IN ('created', 'pending')",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .context("failed to select incomplete expired requests")?;

        sqlx::query("DELETE FROM requests WHERE expired < $1")
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("failed to delete expired requests")?;

        tx.commit().await.context("failed to commit transaction")?;
        Ok(incomplete)
    }

    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool> {
        let found = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM requests CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e2e_kids::jsonb) = 'array' THEN e2e_kids::jsonb ELSE '[]'::jsonb END) AS elem WHERE requests.status IN ('created', 'pending') AND elem = $1)",
        )
        .bind(kid)
        .fetch_one(&self.pool)
        .await
        .context("failed to check kid in-flight")?;
        Ok(found)
    }
}

#[derive(sqlx::FromRow)]
struct PgRequestRow {
    request_id: String,
    status: String,
    daemon_public_key: String,
}

impl From<PgRequestRow> for RequestRow {
    fn from(r: PgRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            daemon_public_key: r.daemon_public_key,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PgFullRequestRow {
    request_id: String,
    status: String,
    expired: String,
    signature: Option<String>,
    client_ids: String,
    daemon_public_key: String,
    daemon_enc_public_key: String,
    pairing_ids: String,
    e2e_kids: String,
    encrypted_payloads: Option<String>,
    unavailable_client_ids: String,
}

impl From<PgFullRequestRow> for FullRequestRow {
    fn from(r: PgFullRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            expired: r.expired,
            signature: r.signature,
            client_ids: r.client_ids,
            daemon_public_key: r.daemon_public_key,
            daemon_enc_public_key: r.daemon_enc_public_key,
            pairing_ids: r.pairing_ids,
            e2e_kids: r.e2e_kids,
            encrypted_payloads: r.encrypted_payloads,
            unavailable_client_ids: r.unavailable_client_ids,
        }
    }
}
