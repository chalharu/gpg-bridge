use anyhow::Context;
use async_trait::async_trait;
use sqlx::{Database, FromRow, Pool};

use crate::repository::{
    AuditLogRepository, AuditLogRow, CleanupRepository, ClientPairingRepository, ClientPairingRow,
    ClientRepository, ClientRow, JtiRepository, PairingRepository, PairingRow,
    SigningKeyRepository, SigningKeyRow,
};

#[derive(Debug, Clone)]
pub struct SqlRepository<DB: Database> {
    pub(crate) pool: Pool<DB>,
}

#[derive(FromRow)]
struct SigningKeyRecord {
    kid: String,
    private_key: String,
    public_key: String,
    created_at: String,
    expires_at: String,
    is_active: bool,
}

impl From<SigningKeyRecord> for SigningKeyRow {
    fn from(record: SigningKeyRecord) -> Self {
        Self {
            kid: record.kid,
            private_key: record.private_key,
            public_key: record.public_key,
            created_at: record.created_at,
            expires_at: record.expires_at,
            is_active: record.is_active,
        }
    }
}

#[derive(FromRow)]
struct ClientRecord {
    client_id: String,
    created_at: String,
    updated_at: String,
    device_token: String,
    device_jwt_issued_at: String,
    public_keys: String,
    default_kid: String,
    gpg_keys: String,
}

impl From<ClientRecord> for ClientRow {
    fn from(record: ClientRecord) -> Self {
        Self {
            client_id: record.client_id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            device_token: record.device_token,
            device_jwt_issued_at: record.device_jwt_issued_at,
            public_keys: record.public_keys,
            default_kid: record.default_kid,
            gpg_keys: record.gpg_keys,
        }
    }
}

#[derive(FromRow)]
struct PairingRecord {
    pairing_id: String,
    expired: String,
    client_id: Option<String>,
}

impl From<PairingRecord> for PairingRow {
    fn from(record: PairingRecord) -> Self {
        Self {
            pairing_id: record.pairing_id,
            expired: record.expired,
            client_id: record.client_id,
        }
    }
}

#[derive(FromRow)]
struct ClientPairingRecord {
    client_id: String,
    pairing_id: String,
    client_jwt_issued_at: String,
}

impl From<ClientPairingRecord> for ClientPairingRow {
    fn from(record: ClientPairingRecord) -> Self {
        Self {
            client_id: record.client_id,
            pairing_id: record.pairing_id,
            client_jwt_issued_at: record.client_jwt_issued_at,
        }
    }
}

#[async_trait]
trait CommonJtiRepository: Send + Sync {
    async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool>;
    async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> JtiRepository for T
where
    T: CommonJtiRepository + Send + Sync,
{
    async fn store_jti(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
        self.store_jti_common(jti, expired).await
    }

    async fn delete_expired_jtis(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_jtis_common(now).await
    }
}

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
trait CommonCleanupRepository: Send + Sync {
    async fn delete_unpaired_clients_common(&self, cutoff: &str) -> anyhow::Result<u64>;
    async fn delete_expired_device_jwt_clients_common(&self, cutoff: &str) -> anyhow::Result<u64>;
    async fn delete_expired_client_jwt_pairings_common(&self, cutoff: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> CleanupRepository for T
where
    T: CommonCleanupRepository + Send + Sync,
{
    async fn delete_unpaired_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.delete_unpaired_clients_common(cutoff).await
    }

    async fn delete_expired_device_jwt_clients(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.delete_expired_device_jwt_clients_common(cutoff).await
    }

    async fn delete_expired_client_jwt_pairings(&self, cutoff: &str) -> anyhow::Result<u64> {
        self.delete_expired_client_jwt_pairings_common(cutoff).await
    }
}

#[async_trait]
trait CommonSigningKeyRepository: Send + Sync {
    async fn store_signing_key_common(&self, key: &SigningKeyRow) -> anyhow::Result<()>;
    async fn get_active_signing_key_common(&self) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn get_signing_key_by_kid_common(
        &self,
        kid: &str,
    ) -> anyhow::Result<Option<SigningKeyRow>>;
    async fn retire_signing_key_common(&self, kid: &str) -> anyhow::Result<bool>;
    async fn delete_expired_signing_keys_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> SigningKeyRepository for T
where
    T: CommonSigningKeyRepository + Send + Sync,
{
    async fn store_signing_key(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
        self.store_signing_key_common(key).await
    }

    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        self.get_active_signing_key_common().await
    }

    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        self.get_signing_key_by_kid_common(kid).await
    }

    async fn retire_signing_key(&self, kid: &str) -> anyhow::Result<bool> {
        self.retire_signing_key_common(kid).await
    }

    async fn delete_expired_signing_keys(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_signing_keys_common(now).await
    }
}

#[async_trait]
trait CommonClientRepository: Send + Sync {
    async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>>;
    async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()>;
    async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool>;
    async fn client_by_device_token_common(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>>;
    async fn update_client_device_token_common(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_default_kid_common(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()>;
    async fn update_device_jwt_issued_at_common(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()>;
    async fn update_client_public_keys_common(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;
    async fn update_client_gpg_keys_common(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
impl<T> ClientRepository for T
where
    T: CommonClientRepository + Send + Sync,
{
    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        self.get_client_by_id_common(client_id).await
    }

    async fn create_client(&self, row: &ClientRow) -> anyhow::Result<()> {
        self.create_client_common(row).await
    }

    async fn client_exists(&self, client_id: &str) -> anyhow::Result<bool> {
        self.client_exists_common(client_id).await
    }

    async fn client_by_device_token(
        &self,
        device_token: &str,
    ) -> anyhow::Result<Option<ClientRow>> {
        self.client_by_device_token_common(device_token).await
    }

    async fn update_client_device_token(
        &self,
        client_id: &str,
        device_token: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_client_device_token_common(client_id, device_token, updated_at)
            .await
    }

    async fn update_client_default_kid(
        &self,
        client_id: &str,
        default_kid: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_client_default_kid_common(client_id, default_kid, updated_at)
            .await
    }

    async fn delete_client(&self, client_id: &str) -> anyhow::Result<()> {
        self.delete_client_common(client_id).await
    }

    async fn update_device_jwt_issued_at(
        &self,
        client_id: &str,
        issued_at: &str,
        updated_at: &str,
    ) -> anyhow::Result<()> {
        self.update_device_jwt_issued_at_common(client_id, issued_at, updated_at)
            .await
    }

    async fn update_client_public_keys(
        &self,
        client_id: &str,
        public_keys: &str,
        default_kid: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_public_keys_common(
            client_id,
            public_keys,
            default_kid,
            updated_at,
            expected_updated_at,
        )
        .await
    }

    async fn update_client_gpg_keys(
        &self,
        client_id: &str,
        gpg_keys: &str,
        updated_at: &str,
        expected_updated_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_gpg_keys_common(client_id, gpg_keys, updated_at, expected_updated_at)
            .await
    }
}

#[async_trait]
trait CommonPairingRepository: Send + Sync {
    async fn create_pairing_common(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()>;
    async fn get_pairing_by_id_common(
        &self,
        pairing_id: &str,
    ) -> anyhow::Result<Option<PairingRow>>;
    async fn consume_pairing_common(
        &self,
        pairing_id: &str,
        client_id: &str,
    ) -> anyhow::Result<bool>;
    async fn count_unconsumed_pairings_common(&self, now: &str) -> anyhow::Result<i64>;
    async fn delete_expired_pairings_common(&self, now: &str) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T> PairingRepository for T
where
    T: CommonPairingRepository + Send + Sync,
{
    async fn create_pairing(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
        self.create_pairing_common(pairing_id, expired).await
    }

    async fn get_pairing_by_id(&self, pairing_id: &str) -> anyhow::Result<Option<PairingRow>> {
        self.get_pairing_by_id_common(pairing_id).await
    }

    async fn consume_pairing(&self, pairing_id: &str, client_id: &str) -> anyhow::Result<bool> {
        self.consume_pairing_common(pairing_id, client_id).await
    }

    async fn count_unconsumed_pairings(&self, now: &str) -> anyhow::Result<i64> {
        self.count_unconsumed_pairings_common(now).await
    }

    async fn delete_expired_pairings(&self, now: &str) -> anyhow::Result<u64> {
        self.delete_expired_pairings_common(now).await
    }
}

#[async_trait]
trait CommonClientPairingRepository: Send + Sync {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>>;
    async fn create_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()>;
    async fn delete_client_pairing_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool>;
    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)>;
    async fn update_client_jwt_issued_at_common(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
impl<T> ClientPairingRepository for T
where
    T: CommonClientPairingRepository + Send + Sync,
{
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        self.get_client_pairings_common(client_id).await
    }

    async fn create_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
        client_jwt_issued_at: &str,
    ) -> anyhow::Result<()> {
        self.create_client_pairing_common(client_id, pairing_id, client_jwt_issued_at)
            .await
    }

    async fn delete_client_pairing(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<bool> {
        self.delete_client_pairing_common(client_id, pairing_id)
            .await
    }

    async fn delete_client_pairing_and_cleanup(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        self.delete_client_pairing_and_cleanup_common(client_id, pairing_id)
            .await
    }

    async fn update_client_jwt_issued_at(
        &self,
        client_id: &str,
        pairing_id: &str,
        issued_at: &str,
    ) -> anyhow::Result<bool> {
        self.update_client_jwt_issued_at_common(client_id, pairing_id, issued_at)
            .await
    }
}

macro_rules! impl_common_jti_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonJtiRepository for $repo {
            async fn store_jti_common(&self, jti: &str, expired: &str) -> anyhow::Result<bool> {
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

            async fn delete_expired_jtis_common(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM jtis WHERE expired < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired jtis")?;
                Ok(result.rows_affected())
            }
        }
    };
}

macro_rules! impl_common_audit_log_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonAuditLogRepository for $repo {
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
    };
}

macro_rules! impl_common_cleanup_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonCleanupRepository for $repo {
            async fn delete_unpaired_clients_common(&self, cutoff: &str) -> anyhow::Result<u64> {
                let result = sqlx::query(
                    "DELETE FROM clients WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM client_pairings WHERE client_pairings.client_id = clients.client_id)",
                )
                .bind(cutoff)
                .execute(&self.pool)
                .await
                .context("failed to delete unpaired clients")?;
                Ok(result.rows_affected())
            }

            async fn delete_expired_device_jwt_clients_common(&self, cutoff: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM clients WHERE device_jwt_issued_at < $1")
                    .bind(cutoff)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired device_jwt clients")?;
                Ok(result.rows_affected())
            }

            async fn delete_expired_client_jwt_pairings_common(&self, cutoff: &str) -> anyhow::Result<u64> {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .context("failed to begin transaction")?;
                let deleted = sqlx::query("DELETE FROM client_pairings WHERE client_jwt_issued_at < $1")
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await
                    .context("failed to delete expired client_jwt pairings")?;
                let removed = deleted.rows_affected();
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

macro_rules! impl_common_signing_key_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonSigningKeyRepository for $repo {
            async fn store_signing_key_common(&self, key: &SigningKeyRow) -> anyhow::Result<()> {
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

            async fn get_active_signing_key_common(&self) -> anyhow::Result<Option<SigningKeyRow>> {
                let row = sqlx::query_as::<_, SigningKeyRecord>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE is_active = TRUE LIMIT 1",
                )
                .fetch_optional(&self.pool)
                .await
                .context("failed to get active signing key")?;
                Ok(row.map(Into::into))
            }

            async fn get_signing_key_by_kid_common(
                &self,
                kid: &str,
            ) -> anyhow::Result<Option<SigningKeyRow>> {
                let row = sqlx::query_as::<_, SigningKeyRecord>(
                    "SELECT kid, private_key, public_key, created_at, expires_at, is_active FROM signing_keys WHERE kid = $1",
                )
                .bind(kid)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get signing key by kid")?;
                Ok(row.map(Into::into))
            }

            async fn retire_signing_key_common(&self, kid: &str) -> anyhow::Result<bool> {
                let result = sqlx::query("UPDATE signing_keys SET is_active = FALSE WHERE kid = $1")
                    .bind(kid)
                    .execute(&self.pool)
                    .await
                    .context("failed to retire signing key")?;
                Ok(result.rows_affected() > 0)
            }

            async fn delete_expired_signing_keys_common(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM signing_keys WHERE expires_at < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired signing keys")?;
                Ok(result.rows_affected())
            }
        }
    };
}

macro_rules! impl_common_client_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonClientRepository for $repo {
            async fn get_client_by_id_common(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
                let row = sqlx::query_as::<_, ClientRecord>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE client_id = $1",
                )
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by id")?;
                Ok(row.map(Into::into))
            }

            async fn create_client_common(&self, row: &ClientRow) -> anyhow::Result<()> {
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

            async fn client_exists_common(&self, client_id: &str) -> anyhow::Result<bool> {
                let count =
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM clients WHERE client_id = $1")
                        .bind(client_id)
                        .fetch_one(&self.pool)
                        .await
                        .context("failed to check client existence")?;
                Ok(count > 0)
            }

            async fn client_by_device_token_common(
                &self,
                device_token: &str,
            ) -> anyhow::Result<Option<ClientRow>> {
                let row = sqlx::query_as::<_, ClientRecord>(
                    "SELECT client_id, created_at, updated_at, device_token, device_jwt_issued_at, public_keys, default_kid, gpg_keys FROM clients WHERE device_token = $1",
                )
                .bind(device_token)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get client by device_token")?;
                Ok(row.map(Into::into))
            }

            async fn update_client_device_token_common(
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

            async fn update_client_default_kid_common(
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

            async fn delete_client_common(&self, client_id: &str) -> anyhow::Result<()> {
                sqlx::query("DELETE FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete client")?;
                Ok(())
            }

            async fn update_device_jwt_issued_at_common(
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

            async fn update_client_public_keys_common(
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

            async fn update_client_gpg_keys_common(
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
        }
    };
}

macro_rules! impl_common_pairing_repository {
    ($repo:ty) => {
        #[async_trait]
        impl CommonPairingRepository for $repo {
            async fn create_pairing_common(&self, pairing_id: &str, expired: &str) -> anyhow::Result<()> {
                sqlx::query("INSERT INTO pairings (pairing_id, expired) VALUES ($1, $2)")
                    .bind(pairing_id)
                    .bind(expired)
                    .execute(&self.pool)
                    .await
                    .context("failed to create pairing")?;
                Ok(())
            }

            async fn get_pairing_by_id_common(
                &self,
                pairing_id: &str,
            ) -> anyhow::Result<Option<PairingRow>> {
                let row = sqlx::query_as::<_, PairingRecord>(
                    "SELECT pairing_id, expired, client_id FROM pairings WHERE pairing_id = $1",
                )
                .bind(pairing_id)
                .fetch_optional(&self.pool)
                .await
                .context("failed to get pairing by id")?;
                Ok(row.map(Into::into))
            }

            async fn consume_pairing_common(
                &self,
                pairing_id: &str,
                client_id: &str,
            ) -> anyhow::Result<bool> {
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

            async fn count_unconsumed_pairings_common(&self, now: &str) -> anyhow::Result<i64> {
                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM pairings WHERE client_id IS NULL AND expired > $1",
                )
                .bind(now)
                .fetch_one(&self.pool)
                .await
                .context("failed to count unconsumed pairings")?;
                Ok(count)
            }

            async fn delete_expired_pairings_common(&self, now: &str) -> anyhow::Result<u64> {
                let result = sqlx::query("DELETE FROM pairings WHERE expired < $1")
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .context("failed to delete expired pairings")?;
                Ok(result.rows_affected())
            }
        }
    };
}

impl_common_jti_repository!(crate::repository::PostgresRepository);
impl_common_jti_repository!(crate::repository::SqliteRepository);
impl_common_audit_log_repository!(crate::repository::PostgresRepository);
impl_common_audit_log_repository!(crate::repository::SqliteRepository);
impl_common_cleanup_repository!(crate::repository::PostgresRepository);
impl_common_cleanup_repository!(crate::repository::SqliteRepository);
impl_common_signing_key_repository!(crate::repository::PostgresRepository);
impl_common_signing_key_repository!(crate::repository::SqliteRepository);
impl_common_client_repository!(crate::repository::PostgresRepository);
impl_common_client_repository!(crate::repository::SqliteRepository);
impl_common_pairing_repository!(crate::repository::PostgresRepository);
impl_common_pairing_repository!(crate::repository::SqliteRepository);

#[async_trait]
impl CommonClientPairingRepository for crate::repository::PostgresRepository {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, ClientPairingRecord>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_client_pairing_common(
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

    async fn delete_client_pairing_common(
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

    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;
        let deleted =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = deleted.rows_affected() > 0;
        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, i64>(
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

    async fn update_client_jwt_issued_at_common(
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
}

#[async_trait]
impl CommonClientPairingRepository for crate::repository::SqliteRepository {
    async fn get_client_pairings_common(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Vec<ClientPairingRow>> {
        let rows = sqlx::query_as::<_, ClientPairingRecord>(
            "SELECT client_id, pairing_id, client_jwt_issued_at FROM client_pairings WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .context("failed to get client pairings")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_client_pairing_common(
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

    async fn delete_client_pairing_common(
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

    async fn delete_client_pairing_and_cleanup_common(
        &self,
        client_id: &str,
        pairing_id: &str,
    ) -> anyhow::Result<(bool, bool)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("failed to begin transaction")?;
        let deleted =
            sqlx::query("DELETE FROM client_pairings WHERE client_id = $1 AND pairing_id = $2")
                .bind(client_id)
                .bind(pairing_id)
                .execute(&mut *tx)
                .await
                .context("failed to delete client pairing")?;
        let pairing_deleted = deleted.rows_affected() > 0;
        let mut client_deleted = false;
        if pairing_deleted {
            let remaining = sqlx::query_scalar::<_, i64>(
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

    async fn update_client_jwt_issued_at_common(
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
}
