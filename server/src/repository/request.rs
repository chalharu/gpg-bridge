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
