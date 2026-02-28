use anyhow::Context;
use async_trait::async_trait;
use sqlx::SqlitePool;

use super::{
    AuditLogRow, ClientPairingRow, ClientRow, CreateRequestRow, FullRequestRow, MIGRATOR,
    PairingRow, RequestRow, SignatureRepository, SigningKeyRow,
};

#[derive(Debug, Clone)]
pub struct SqliteRepository {
    pub(crate) pool: SqlitePool,
}

#[async_trait]
impl SignatureRepository for SqliteRepository {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run sqlite migrations")
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("sqlite health check failed")?;

        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO signing_keys (kid, private_key, public_key, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&key.kid)
        .bind(&key.private_key)
        .bind(&key.public_key)
        .bind(&key.created_at)
        .bind(&key.expires_at)
        .bind(key.is_active)
        .execute(&self.pool)
        .await
        .context("failed to store signing key")?;
        Ok(())
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SqliteSigningKeyRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("failed to get active signing key")?;
        Ok(row.map(Into::into))
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        let row = sqlx::query_as::<_, SqliteSigningKeyRow>(
            "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get signing key by kid")?;
        Ok(row.map(Into::into))
    }

    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE signing_keys SET is_active = FALSE WHERE kid = $1")
            .bind(kid)
            .execute(&self.pool)
            .await
            .context("failed to retire signing key")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM signing_keys WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired signing keys")?;
        Ok(result.rows_affected())
    }

    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, SqliteClientRow>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by id")?;
        Ok(row.map(Into::into))
    }

    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&row.client_id)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .bind(&row.device_token)
        .bind(&row.device_jwt_issued_at)
        .bind(&row.public_keys)
        .bind(&row.default_kid)
        .bind(&row.gpg_keys)
        .execute(&self.pool)
        .await
        .context("failed to create client")?;
        Ok(())
    }

    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        let count =
            sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(&self.pool)
                .await
                .context("failed to check client existence")?;
        Ok(count > 0)
    }

    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        let row = sqlx::query_as::<_, SqliteClientRow>(
            "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
        )
        .bind(device_token)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get client by device_token")?;
        Ok(row.map(Into::into))
    }

    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET device_token = $1, updated_at = $2 WHERE client_id = $3")
            .bind(device_token)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client device_token")?;
        Ok(())
    }

    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE clients SET default_kid = $1, updated_at = $2 WHERE client_id = $3")
            .bind(default_kid)
            .bind(updated_at)
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to update client default_kid")?;
        Ok(())
    }

    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .context("failed to delete client")?;
        Ok(())
    }

    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE clients SET device_jwt_issued_at = $1, updated_at = $2 WHERE client_id = $3",
        )
        .bind(issued_at)
        .bind(updated_at)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .context("failed to update device_jwt_issued_at")?;
        Ok(())
    }

    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, SqliteClientPairingRow>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ($1, $2, $3)",
        )
        .bind(client_id)
        .bind(pairing_id)
        .bind(client_jwt_issued_at)
        .execute(&self.pool)
        .await
        .context("failed to create client pairing")?;
        Ok(())
    }

    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        let result =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .context("failed to delete client pairing")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;

        let del =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = del.rows_affected() > 0;

        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, i32>(
                "SELECT COUNT(*) FROM client_pairings WHERE client_id = $1",
            )
            .bind(client_id)
            .fetch_one(&mut *tx)
            .await
            .context("failed to count remaining pairings")?;

            if remaining == 0 {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete client")?;
                client_deleted = true;
            }
        }

        tx.commit().await.context("failed to commit transaction")?;
        Ok((pairing_deleted, client_deleted))
    }

    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE client_pairings SET client_jwt_issued_at = $1 WHERE client_id = $2 AND pairing_id = $3",
        )
        .bind(issued_at)
        .bind(client_id)
        .bind(pairing_id)
        .execute(&self.pool)
        .await
        .context("failed to update client_jwt_issued_at")?;
        Ok(result.rows_affected() > 0)
    }

    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO pairings (pairing_id, expired) VALUES ($1, $2)")
            .bind(pairing_id)
            .bind(expired)
            .execute(&self.pool)
            .await
            .context("failed to create pairing")?;
        Ok(())
    }

    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        let row = sqlx::query_as::<_, SqlitePairingRow>(
            "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
        )
        .bind(pairing_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed to get pairing by id")?;
        Ok(row.map(Into::into))
    }

    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE pairings SET client_id = $1 WHERE pairing_id = $2 AND client_id IS NULL",
        )
        .bind(client_id)
        .bind(pairing_id)
        .execute(&self.pool)
        .await
        .context("failed to consume pairing")?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64> {
        let count = sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM pairings WHERE client_id IS NULL AND expired > $1",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("failed to count unconsumed pairings")?;
        Ok(i64::from(count))
    }

    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM pairings WHERE expired < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired pairings")?;
        Ok(result.rows_affected())
    }

    async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>> {
        let row = sqlx::query_as::<_, SqliteRequestRow>(
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
        let row = sqlx::query_as::<_, SqliteFullRequestRow>(
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
        let count = sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM requests WHERE status IN ('created', 'pending') AND EXISTS (SELECT 1 FROM json_each(requests.client_ids) WHERE json_each.value = $1) AND json_extract(requests.pairing_ids, '$.\"' || $1 || '\"') = $2",
        )
        .bind(client_id)
        .bind(pairing_id)
        .fetch_one(&self.pool)
        .await
        .context("failed to count pending requests for pairing")?;
        Ok(i64::from(count))
    }

    async fn create_audit_log(&self, row: &AuditLogRow) -> anyhow::Result<()> {
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

    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET public_keys = $1, default_kid = $2, updated_at = $3 WHERE client_id = $4 AND updated_at = $5",
        )
        .bind(public_keys)
        .bind(default_kid)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client public_keys")?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE clients SET gpg_keys = $1, updated_at = $2 WHERE client_id = $3 AND updated_at = $4",
        )
        .bind(gpg_keys)
        .bind(updated_at)
        .bind(client_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .context("failed to update client gpg_keys")?;
        Ok(result.rows_affected() > 0)
    }

    async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool> {
        let count = sqlx::query_scalar::<_, i32>(
            "SELECT EXISTS(SELECT 1 FROM requests, json_each(requests.e2e_kids) AS je WHERE requests.status IN ('created', 'pending') AND je.value = $1)",
        )
        .bind(kid)
        .fetch_one(&self.pool)
        .await
        .context("failed to check kid in-flight")?;
        Ok(count != 0)
    }

    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "INSERT INTO jtis (jti, expired) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expired)
        .execute(&self.pool)
        .await
        .context("failed to store jti")?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .context("failed to delete expired jtis")?;
        Ok(result.rows_affected())
    }

    async fn get_pending_requests_for_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<FullRequestRow>> {
        let rows = sqlx::query_as::<_, SqliteFullRequestRow>(
            "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE status = 'pending' AND expired > datetime('now') AND EXISTS (SELECT 1 FROM json_each(requests.client_ids) WHERE json_each.value = $1) AND NOT EXISTS (SELECT 1 FROM json_each(requests.unavailable_client_ids) WHERE json_each.value = $1)",
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
            "SELECT unavailable_client_ids, client_ids, status FROM requests WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .context("failed to read request for unavailable update")?;

        let (unavailable_json, client_ids, status) = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        if status != "pending" {
            return Ok(None);
        }

        let mut unavailable: Vec<String> = serde_json::from_str(&unavailable_json)
            .context("invalid unavailable_client_ids JSON")?;
        if unavailable.contains(&client_id.to_owned()) {
            return Ok(None);
        }

        unavailable.push(client_id.to_owned());
        let updated = serde_json::to_string(&unavailable)
            .context("failed to serialize unavailable_client_ids")?;

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

    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM clients WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id)",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .context("failed to delete unpaired clients")?;
        Ok(result.rows_affected())
    }

    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM clients WHERE device_jwt_issued_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .context("failed to delete expired device_jwt clients")?;
        Ok(result.rows_affected())
    }

    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;

        let del = sqlx::query("DELETE FROM client_pairings WHERE client_jwt_issued_at < $1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .context("failed to delete expired client_jwt pairings")?;
        let removed = del.rows_affected();

        sqlx::query(
            "DELETE FROM clients WHERE NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id) AND NOT EXISTS (SELECT 1 FROM pairings WHERE pairings.client_id = clients.client_id)",
        )
        .execute(&mut *tx)
        .await
        .context("failed to delete orphaned clients")?;

        tx.commit().await.context("failed to commit transaction")?;
        Ok(removed)
    }
}

#[derive(sqlx::FromRow)]
struct SqliteSigningKeyRow {
    kid: String,
    private_key: String,
    public_key: String,
    created_at: String,
    expires_at: String,
    is_active: bool,
}

impl From<SqliteSigningKeyRow> for SigningKeyRow {
    fn from(r: SqliteSigningKeyRow) -> Self {
        Self {
            kid: r.kid,
            private_key: r.private_key,
            public_key: r.public_key,
            created_at: r.created_at,
            expires_at: r.expires_at,
            is_active: r.is_active,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteClientRow {
    client_id: String,
    created_at: String,
    updated_at: String,
    device_token: String,
    device_jwt_issued_at: String,
    public_keys: String,
    default_kid: String,
    gpg_keys: String,
}

impl From<SqliteClientRow> for ClientRow {
    fn from(r: SqliteClientRow) -> Self {
        Self {
            client_id: r.client_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            device_token: r.device_token,
            device_jwt_issued_at: r.device_jwt_issued_at,
            public_keys: r.public_keys,
            default_kid: r.default_kid,
            gpg_keys: r.gpg_keys,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteClientPairingRow {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<SqliteClientPairingRow> for ClientPairingRow {
    fn from(r: SqliteClientPairingRow) -> Self {
        Self {
            client_id: r.client_id,
            pairing_id: r.pairing_id,
            client_jwt_issued_at: r.client_jwt_issued_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqlitePairingRow {
    pairing_id: String,
    expired: String,
    client_id: Option<String>,
}

impl From<SqlitePairingRow> for PairingRow {
    fn from(r: SqlitePairingRow) -> Self {
        Self {
            pairing_id: r.pairing_id,
            expired: r.expired,
            client_id: r.client_id,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteRequestRow {
    request_id: String,
    status: String,
    daemon_public_key: String,
}

impl From<SqliteRequestRow> for RequestRow {
    fn from(r: SqliteRequestRow) -> Self {
        Self {
            request_id: r.request_id,
            status: r.status,
            daemon_public_key: r.daemon_public_key,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteFullRequestRow {
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

impl From<SqliteFullRequestRow> for FullRequestRow {
    fn from(r: SqliteFullRequestRow) -> Self {
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

#[cfg(test)]
mod tests {
    use super::SqliteRepository;
    use crate::config::AppConfig;
    use crate::repository::{MIGRATOR, SignatureRepository, SigningKeyRow, build_repository};
    use sqlx::SqlitePool;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    fn sqlite_test_config() -> AppConfig {
        AppConfig {
            server_host: "127.0.0.1".to_owned(),
            server_port: 3000,
            database_url: "sqlite::memory:".to_owned(),
            db_max_connections: 4,
            db_min_connections: 1,
            db_acquire_timeout_seconds: 5,
            log_level: "info".to_owned(),
            log_format: "plain".to_owned(),
            signing_key_secret: "test-secret-key!".to_owned(),
            base_url: "http://localhost:3000".to_owned(),
            rate_limit_strict_quota: 10,
            rate_limit_strict_window_seconds: 60,
            rate_limit_standard_quota: 60,
            rate_limit_standard_window_seconds: 60,
            rate_limit_sse_max_per_ip: 20,
            rate_limit_sse_max_per_key: 1,
            device_jwt_validity_seconds: 31_536_000,
            pairing_jwt_validity_seconds: 300,
            client_jwt_validity_seconds: 31_536_000,
            request_jwt_validity_seconds: 300,
            unconsumed_pairing_limit: 100,
            fcm_service_account_key_path: None,
            fcm_project_id: None,
            cleanup_interval_seconds: 60,
            unpaired_client_max_age_hours: 24,
        }
    }

    /// Build an in-memory SQLite pool with the same connect options used in
    /// production (`foreign_keys(true)`, WAL journal mode).  This lets tests
    /// exercise the real connection settings without needing to downcast
    /// through `Arc<dyn SignatureRepository>`.
    async fn build_sqlite_test_pool() -> SqlitePool {
        let options = "sqlite::memory:"
            .parse::<SqliteConnectOptions>()
            .unwrap()
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);

        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sqlite_repository_runs_migration_and_health_check() {
        let config = sqlite_test_config();
        let repository = build_repository(&config).await.unwrap();

        repository.run_migrations().await.unwrap();
        repository.health_check().await.unwrap();
        assert_eq!(repository.backend_name(), "sqlite");
    }

    #[tokio::test]
    async fn sqlite_enforces_foreign_key_constraints() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();

        // Positive case: insert a valid client, then a client_pairings row referencing it.
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ('client-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', '[]', 'kid-1', '[]')",
        )
        .execute(&pool)
        .await
        .expect("inserting a valid client should succeed");

        sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .expect("inserting a client_pairings row with valid FK should succeed");

        // Negative case: inserting a client_pairings row referencing a non-existent client
        // must fail because of the foreign key constraint on client_id.
        let result = sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('nonexistent', 'pair-2', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await;

        let err = result
            .expect_err("foreign key constraint should reject insert with non-existent client_id");
        let msg = err.to_string();
        assert!(
            msg.contains("FOREIGN KEY constraint failed"),
            "expected FK violation error, got: {msg}",
        );
    }

    // ---- signing_keys repository tests ----

    fn make_signing_key_row(kid: &str, is_active: bool, expires_at: &str) -> SigningKeyRow {
        SigningKeyRow {
            kid: kid.to_owned(),
            private_key: "encrypted-private".to_owned(),
            public_key: "{\"kty\":\"EC\"}".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            expires_at: expires_at.to_owned(),
            is_active,
        }
    }

    #[tokio::test]
    async fn store_and_get_active_signing_key() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-1", true, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let active = repo.get_active_signing_key().await.unwrap().unwrap();
        assert_eq!(active.kid, "kid-1");
        assert!(active.is_active);
    }

    #[tokio::test]
    async fn get_signing_key_by_kid() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-2", false, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let found = repo.get_signing_key_by_kid("kid-2").await.unwrap().unwrap();
        assert_eq!(found.kid, "kid-2");
        assert!(!found.is_active);

        let missing = repo.get_signing_key_by_kid("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn retire_signing_key_sets_inactive() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let key = make_signing_key_row("kid-3", true, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&key).await.unwrap();

        let updated = repo.retire_signing_key("kid-3").await.unwrap();
        assert!(updated);

        let retired = repo.get_signing_key_by_kid("kid-3").await.unwrap().unwrap();
        assert!(!retired.is_active);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn retire_nonexistent_signing_key_returns_false() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let updated = repo.retire_signing_key("nonexistent").await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn delete_expired_signing_keys_removes_old() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let expired = make_signing_key_row("kid-old", false, "2025-01-01T00:00:00Z");
        let valid = make_signing_key_row("kid-new", false, "2027-01-01T00:00:00Z");
        repo.store_signing_key(&expired).await.unwrap();
        repo.store_signing_key(&valid).await.unwrap();

        let deleted = repo
            .delete_expired_signing_keys("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        assert!(
            repo.get_signing_key_by_kid("kid-old")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_signing_key_by_kid("kid-new")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn no_active_key_returns_none() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(repo.get_active_signing_key().await.unwrap().is_none());
    }

    // ---- clients repository tests ----

    async fn insert_test_client(pool: &SqlitePool, client_id: &str, public_keys: &str) {
        sqlx::query(
            "INSERT INTO clients (client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys) VALUES ($1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'tok', '2026-01-01T00:00:00Z', $2, 'kid-1', '[]')",
        )
        .bind(client_id)
        .bind(public_keys)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_client_by_id_found() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_client(&pool, "client-1", "[]").await;
        let client = repo.get_client_by_id("client-1").await.unwrap().unwrap();
        assert_eq!(client.client_id, "client-1");
    }

    #[tokio::test]
    async fn get_client_by_id_not_found() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(
            repo.get_client_by_id("nonexistent")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ---- client_pairings repository tests ----

    #[tokio::test]
    async fn get_client_pairings_returns_matching() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_client(&pool, "client-1", "[]").await;
        sqlx::query(
            "INSERT INTO client_pairings (client_id, pairing_id, client_jwt_issued_at) VALUES ('client-1', 'pair-1', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let pairings = repo.get_client_pairings("client-1").await.unwrap();
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].pairing_id, "pair-1");
    }

    #[tokio::test]
    async fn get_client_pairings_returns_empty_for_unknown() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let pairings = repo.get_client_pairings("nonexistent").await.unwrap();
        assert!(pairings.is_empty());
    }

    // ---- requests repository tests ----

    async fn insert_test_request(pool: &SqlitePool, request_id: &str) {
        sqlx::query(
            "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids) VALUES ($1, 'created', '2027-01-01T00:00:00Z', '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', '{}')",
        )
        .bind(request_id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_request_by_id_found() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_request(&pool, "req-1").await;
        let request = repo.get_request_by_id("req-1").await.unwrap().unwrap();
        assert_eq!(request.request_id, "req-1");
        assert_eq!(request.status, "created");
    }

    #[tokio::test]
    async fn get_request_by_id_not_found() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(
            repo.get_request_by_id("nonexistent")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ---- jtis repository tests ----

    #[tokio::test]
    async fn store_jti_returns_true_for_new() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(
            repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn store_jti_returns_false_for_duplicate() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        assert!(
            repo.store_jti("jti-1", "2027-01-01T00:00:00Z")
                .await
                .unwrap()
        );
        assert!(
            !repo
                .store_jti("jti-1", "2027-01-01T00:00:00Z")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn delete_expired_jtis_removes_old() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        repo.store_jti("jti-old", "2025-01-01T00:00:00Z")
            .await
            .unwrap();
        repo.store_jti("jti-new", "2027-01-01T00:00:00Z")
            .await
            .unwrap();

        let deleted = repo
            .delete_expired_jtis("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        // jti-old was deleted, so storing it again should succeed
        assert!(
            repo.store_jti("jti-old", "2027-01-01T00:00:00Z")
                .await
                .unwrap()
        );
        // jti-new still exists
        assert!(
            !repo
                .store_jti("jti-new", "2027-01-01T00:00:00Z")
                .await
                .unwrap()
        );
    }

    // ---- audit_log repository tests ----

    async fn insert_audit_log(pool: &SqlitePool, log_id: &str, event_type: &str, timestamp: &str) {
        sqlx::query(
            "INSERT INTO audit_log (log_id, timestamp, event_type, request_id) \
             VALUES ($1, $2, $3, 'req-1')",
        )
        .bind(log_id)
        .bind(timestamp)
        .bind(event_type)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn count_audit_logs(pool: &SqlitePool) -> i32 {
        sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM audit_log")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    // ---- delete_expired_requests tests ----

    async fn insert_request_with_status(
        pool: &SqlitePool,
        request_id: &str,
        status: &str,
        expired: &str,
    ) {
        // The CHECK constraint requires specific column combinations per status.
        let (enc, sig) = match status {
            "created" => (None, None),
            "pending" => (Some("{}"), None),
            "approved" => (Some("{}"), Some("sig")),
            "denied" | "unavailable" => (Some("{}"), None),
            _ => (None, None),
        };
        sqlx::query(
            "INSERT INTO requests (request_id, status, expired, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, unavailable_client_ids, encrypted_payloads, signature) VALUES ($1, $2, $3, '[]', '{\"kty\":\"EC\"}', '{\"kty\":\"EC\"}', '{}', '{}', '[]', $4, $5)",
        )
        .bind(request_id)
        .bind(status)
        .bind(expired)
        .bind(enc)
        .bind(sig)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn create_audit_log_inserts_row() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        let row = super::AuditLogRow {
            log_id: "log-1".into(),
            timestamp: "2026-06-01T00:00:00Z".into(),
            event_type: "sign_approved".into(),
            request_id: "req-1".into(),
            request_ip: None,
            target_client_ids: None,
            responding_client_id: Some("client-1".into()),
            error_code: None,
            error_message: None,
        };
        repo.create_audit_log(&row).await.unwrap();
        assert_eq!(count_audit_logs(&pool).await, 1);
    }

    #[tokio::test]
    async fn delete_expired_audit_logs_by_retention() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        // approved (1yr retention): old=2024, new=2026
        insert_audit_log(&pool, "a1", "sign_approved", "2024-01-01T00:00:00Z").await;
        insert_audit_log(&pool, "a2", "sign_approved", "2026-01-01T00:00:00Z").await;
        // created (1yr retention)
        insert_audit_log(&pool, "a3", "sign_request_created", "2024-01-01T00:00:00Z").await;
        // denied (6mo retention): old=2025-01, new=2026
        insert_audit_log(&pool, "a4", "sign_denied", "2025-01-01T00:00:00Z").await;
        insert_audit_log(&pool, "a5", "sign_denied", "2026-01-01T00:00:00Z").await;
        // expired (6mo retention)
        insert_audit_log(&pool, "a6", "sign_expired", "2025-03-01T00:00:00Z").await;
        // cancelled (6mo retention)
        insert_audit_log(&pool, "a7", "sign_cancelled", "2025-02-01T00:00:00Z").await;
        // conflict (3mo retention): old=2025-09, new=2026
        insert_audit_log(&pool, "a8", "sign_result_conflict", "2025-09-01T00:00:00Z").await;
        insert_audit_log(&pool, "a9", "sign_result_conflict", "2026-01-01T00:00:00Z").await;
        // device_unavailable (6mo)
        insert_audit_log(
            &pool,
            "a10",
            "sign_device_unavailable",
            "2025-01-01T00:00:00Z",
        )
        .await;
        // unavailable (6mo)
        insert_audit_log(&pool, "a11", "sign_unavailable", "2025-02-01T00:00:00Z").await;

        assert_eq!(count_audit_logs(&pool).await, 11);

        // Cutoffs: approved_before=2025-06-01, denied_before=2025-12-01, conflict_before=2025-12-01
        let deleted = repo
            .delete_expired_audit_logs(
                "2025-06-01T00:00:00Z",
                "2025-12-01T00:00:00Z",
                "2025-12-01T00:00:00Z",
            )
            .await
            .unwrap();

        // Deleted: a1 (approved old), a3 (created old), a4 (denied old),
        //          a6 (expired old), a7 (cancelled old), a8 (conflict old),
        //          a10 (device_unavailable old), a11 (unavailable old) = 8
        assert_eq!(deleted, 8);
        // Remaining: a2, a5, a9 = 3
        assert_eq!(count_audit_logs(&pool).await, 3);
    }

    #[tokio::test]
    async fn delete_expired_audit_logs_returns_zero_when_empty() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let deleted = repo
            .delete_expired_audit_logs(
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn delete_expired_requests_returns_incomplete_ids() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_request_with_status(&pool, "r-created", "created", "2025-01-01T00:00:00Z").await;
        insert_request_with_status(&pool, "r-pending", "pending", "2025-01-01T00:00:00Z").await;
        insert_request_with_status(&pool, "r-approved", "approved", "2025-01-01T00:00:00Z").await;
        insert_request_with_status(&pool, "r-future", "created", "2027-01-01T00:00:00Z").await;

        let mut ids = repo
            .delete_expired_requests("2026-01-01T00:00:00Z")
            .await
            .unwrap();
        ids.sort();
        assert_eq!(ids, vec!["r-created", "r-pending"]);

        // r-approved also deleted, r-future remains
        assert!(
            repo.get_request_by_id("r-approved")
                .await
                .unwrap()
                .is_none()
        );
        assert!(repo.get_request_by_id("r-future").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_expired_requests_empty_when_none() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool };

        let ids = repo
            .delete_expired_requests("2026-01-01T00:00:00Z")
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    // ---- delete_unpaired_clients tests ----

    #[tokio::test]
    async fn delete_unpaired_clients_removes_old_without_pairings() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        // Old client without pairings
        insert_test_client(&pool, "orphan", "[]").await;

        // Old client WITH pairings
        insert_test_client(&pool, "paired", "[]").await;
        repo.create_client_pairing("paired", "p-1", "2026-01-01T00:00:00Z")
            .await
            .unwrap();

        let deleted = repo
            .delete_unpaired_clients("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        assert!(repo.get_client_by_id("orphan").await.unwrap().is_none());
        assert!(repo.get_client_by_id("paired").await.unwrap().is_some());
    }

    // ---- delete_expired_device_jwt_clients tests ----

    #[tokio::test]
    async fn delete_expired_device_jwt_clients_removes_old() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_client(&pool, "old-jwt", "[]").await;
        insert_test_client(&pool, "new-jwt", "[]").await;

        // new-jwt gets a fresh device_jwt_issued_at
        repo.update_device_jwt_issued_at("new-jwt", "2026-12-01T00:00:00Z", "2026-12-01T00:00:00Z")
            .await
            .unwrap();

        let deleted = repo
            .delete_expired_device_jwt_clients("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        assert!(repo.get_client_by_id("old-jwt").await.unwrap().is_none());
        assert!(repo.get_client_by_id("new-jwt").await.unwrap().is_some());
    }

    // ---- delete_expired_client_jwt_pairings tests ----

    #[tokio::test]
    async fn delete_expired_client_jwt_pairings_removes_and_cascades() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_client(&pool, "c1", "[]").await;
        insert_test_client(&pool, "c2", "[]").await;

        // c1 has one old pairing → will be removed → client deleted
        repo.create_client_pairing("c1", "p-old", "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // c2 has one old + one fresh → only old removed, client stays
        repo.create_client_pairing("c2", "p-old2", "2025-01-01T00:00:00Z")
            .await
            .unwrap();
        repo.create_client_pairing("c2", "p-new", "2026-12-01T00:00:00Z")
            .await
            .unwrap();

        let removed = repo
            .delete_expired_client_jwt_pairings("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(removed, 2); // p-old + p-old2

        // c1 cascade-deleted
        assert!(repo.get_client_by_id("c1").await.unwrap().is_none());

        // c2 still has p-new
        assert!(repo.get_client_by_id("c2").await.unwrap().is_some());
        let pairings = repo.get_client_pairings("c2").await.unwrap();
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].pairing_id, "p-new");
    }

    #[tokio::test]
    async fn delete_expired_client_jwt_pairings_noop_when_nothing_expired() {
        let pool = build_sqlite_test_pool().await;
        MIGRATOR.run(&pool).await.unwrap();
        let repo = SqliteRepository { pool: pool.clone() };

        insert_test_client(&pool, "c1", "[]").await;
        repo.create_client_pairing("c1", "p-1", "2027-01-01T00:00:00Z")
            .await
            .unwrap();

        let removed = repo
            .delete_expired_client_jwt_pairings("2026-06-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(removed, 0);
        assert!(repo.get_client_by_id("c1").await.unwrap().is_some());
    }
}
