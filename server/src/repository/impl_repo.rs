/// Generates a `SignatureRepository` implementation for a database backend.
///
/// # Parameters
///
/// - `$repo` — repository struct type (e.g. `SqliteRepository`)
/// - `backend` — string literal backend name (`"sqlite"` or `"postgres"`)
/// - `count_scalar` — scalar type for `COUNT(*)` (`i32` for SQLite, `i64` for Postgres)
/// - `count_pending_for_pairing_sql` — SQL for counting pending requests per pairing
/// - `get_pending_for_client_sql` — SQL for getting pending requests per client
/// - `add_unavail_select_sql` — SQL for SELECT in `add_unavailable_client_id`
/// - `is_kid_in_flight_sql` — SQL for the `is_kid_in_flight` query
/// - `is_kid_in_flight_scalar` — scalar type returned by the EXISTS query (i32 for
///   SQLite, bool for Postgres)
macro_rules! impl_signature_repository {
    (
        $repo:ty,
        backend = $backend:expr,
        count_scalar = $count_scalar:ty,
        count_pending_for_pairing_sql = $cppf_sql:expr,
        get_pending_for_client_sql = $gpfc_sql:expr,
        add_unavail_select_sql = $aus_sql:expr,
        is_kid_in_flight_sql = $kid_sql:expr,
        is_kid_in_flight_scalar = $kid_scalar:ty $(,)?
    ) => {
        #[async_trait]
        impl SignatureRepository for $repo {
            async fn run_migrations(&self) -> anyhow::Result<()> {
                MIGRATOR
                    .run(&self.pool)
                    .await
                    .context(concat!("failed to run ", $backend, " migrations"))
            }

            async fn health_check(&self) -> anyhow::Result<()> {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(&self.pool)
                    .await
                    .context(concat!($backend, " health check failed"))?;
                Ok(())
            }

            fn backend_name(&self) -> &'static str {
                $backend
            }

            // ---- signing_keys ----

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
                sqlx::query_as::<_, SigningKeyRow>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
                )
                .fetch_optional(&self.pool)
                .await
                .context("failed to get active signing key")
            }

            async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
                sqlx::query_as::<_, SigningKeyRow>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
                )
                .bind(kid)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get signing key by kid")
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

            // ---- clients ----

            async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
                sqlx::query_as::<_, ClientRow>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by id")
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
                    sqlx::query_scalar::<_, $count_scalar>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
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
                sqlx::query_as::<_, ClientRow>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
                )
                .bind(device_token)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by device_token")
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

            // ---- client_pairings ----

            async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
                sqlx::query_as::<_, ClientPairingRow>(
                    "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_all(&self.pool)
                .await
                .context("failed to get client pairings")
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
                    let remaining = sqlx::query_scalar::<_, $count_scalar>(
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

            // ---- pairings ----

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
                sqlx::query_as::<_, PairingRow>(
                    "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
                )
                .bind(pairing_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get pairing by id")
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
                let count = sqlx::query_scalar::<_, $count_scalar>(
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

            // ---- requests ----

            async fn get_request_by_id(&self, request_id: &str) -> anyhow::Result<Option<RequestRow>> {
                sqlx::query_as::<_, RequestRow>(
                    "SELECT request_id, status, daemon_public_key FROM requests WHERE request_id = $1",
                )
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get request by id")
            }

            async fn get_full_request_by_id(
                &self,
                request_id: &str,
            ) -> anyhow::Result<Option<FullRequestRow>> {
                sqlx::query_as::<_, FullRequestRow>(
                    "SELECT request_id, status, expired, signature, client_ids, daemon_public_key, daemon_enc_public_key, pairing_ids, e2e_kids, encrypted_payloads, unavailable_client_ids FROM requests WHERE request_id = $1",
                )
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get full request by id")
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
                let count = sqlx::query_scalar::<_, $count_scalar>($cppf_sql)
                    .bind(client_id)
                    .bind(pairing_id)
                    .fetch_one(&self.pool)
                    .await
                    .context("failed to count pending requests for pairing")?;
                Ok(i64::from(count))
            }

            // ---- audit_log ----

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

            // ---- client key management ----

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

            async fn is_kid_in_flight(&self, kid: &str) -> anyhow::Result<bool> {
                let val = sqlx::query_scalar::<_, $kid_scalar>($kid_sql)
                    .bind(kid)
                    .fetch_one(&self.pool)
                    .await
                    .context("failed to check kid in-flight")?;
                let zero: $kid_scalar = Default::default();
                Ok(val != zero)
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

            // ---- jtis ----

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

            // ---- sign-result ----

            async fn get_pending_requests_for_client(
                &self,
                client_id: &str,
            ) -> anyhow::Result<Vec<FullRequestRow>> {
                sqlx::query_as::<_, FullRequestRow>($gpfc_sql)
                    .bind(client_id)
                    .fetch_all(&self.pool)
                    .await
                    .context("failed to get pending requests for client")
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

                let row = sqlx::query_as::<_, (String, String, String)>($aus_sql)
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

            // ---- background-job cleanup ----

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
    };
}
