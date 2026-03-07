use anyhow::Context;
use async_trait::async_trait;

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

#[async_trait]
pub trait RequestRepository: Send + Sync {
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

    /// Delete expired requests. Returns request_ids of incomplete
    /// (created/pending) requests that were deleted so SSE expired events
    /// can be sent. Completed expired requests are also deleted.
    async fn delete_expired_requests(&self, now: &str) -> anyhow::Result<Vec<String>>;

    /// Check if any in-flight request (status=created/pending) references
    /// this kid in `e2e_kids`.
    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool>;
}

/// Try to append `client_id` to the `unavailable_client_ids` JSON array.
///
/// Returns `Ok(Some((updated_json, client_ids)))` when `client_id` was added,
/// `Ok(None)` when the request is not pending, not found, or `client_id` is
/// already present.
pub(crate) fn try_append_unavailable(
    row: Option<(String, String, String)>,
    client_id: &str,
) -> anyhow::Result<Option<(String, String)>> {
    let (unavailable_json, client_ids, status) = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    if status != "pending" {
        return Ok(None);
    }

    let mut unavailable: Vec<String> =
        serde_json::from_str(&unavailable_json).context("invalid unavailable_client_ids JSON")?;
    if unavailable.contains(&client_id.to_owned()) {
        return Ok(None);
    }

    unavailable.push(client_id.to_owned());
    let updated = serde_json::to_string(&unavailable)
        .context("failed to serialize unavailable_client_ids")?;

    Ok(Some((updated, client_ids)))
}

macro_rules! impl_request_repository {
    (
        $repo_ty:ty,
        $request_row_ty:ty,
        $full_row_ty:ty,
        // COUNT(*) return type and converter for count_pending_requests_for_pairing.
        $pairing_count_ty:ty,
        $pairing_count_map:expr,
        // Backend-specific SQL for JSON membership and NOW()/datetime semantics.
        $pairing_count_sql:expr,
        $pending_sql:expr,
        // Backend-specific row locking behavior for unavailable update reads.
        $unavailable_select_sql:expr,
        // EXISTS return type and converter for is_kid_in_flight.
        $kid_found_ty:ty,
        $kid_found_map:expr,
        $kid_found_sql:expr
    ) => {
        #[async_trait::async_trait]
        impl crate::repository::RequestRepository for $repo_ty {
            async fn get_request_by_id(
                &self,
                request_id: &str,
            ) -> anyhow::Result<Option<crate::repository::RequestRow>> {
                let row = sqlx::query_as::<_, $request_row_ty>(
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
            ) -> anyhow::Result<Option<crate::repository::FullRequestRow>> {
                let row = sqlx::query_as::<_, $full_row_ty>(
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

            async fn create_request(
                &self,
                row: &crate::repository::CreateRequestRow,
            ) -> anyhow::Result<()> {
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
                let count: $pairing_count_ty = sqlx::query_scalar::<_, $pairing_count_ty>($pairing_count_sql)
                    .bind(client_id)
                    .bind(pairing_id)
                    .fetch_one(&self.pool)
                    .await
                    .context("failed to count pending requests for pairing")?;
                Ok(($pairing_count_map)(count))
            }

            async fn get_pending_requests_for_client(
                &self,
                client_id: &str,
            ) -> anyhow::Result<Vec<crate::repository::FullRequestRow>> {
                let rows = sqlx::query_as::<_, $full_row_ty>($pending_sql)
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

                let row = sqlx::query_as::<_, (String, String, String)>($unavailable_select_sql)
                    .bind(request_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .context("failed to read request for unavailable update")?;

                let (updated, client_ids) = match crate::repository::request::try_append_unavailable(row, client_id)? {
                    Some(value) => value,
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
                let found: $kid_found_ty = sqlx::query_scalar::<_, $kid_found_ty>($kid_found_sql)
                    .bind(kid)
                    .fetch_one(&self.pool)
                    .await
                    .context("failed to check kid in-flight")?;
                Ok(($kid_found_map)(found))
            }
        }
    };
}

pub(crate) use impl_request_repository;
