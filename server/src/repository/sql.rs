use sqlx::{Database, FromRow, Pool};

mod audit_log;
mod cleanup;
mod client;
mod client_pairing;
mod jti;
mod pairing;
mod signing_key;

#[derive(Debug, Clone)]
pub struct SqlRepository<DB: Database> {
    pub(crate) pool: Pool<DB>,
}

#[derive(FromRow)]
pub(super) struct SigningKeyRecord {
    pub(super) kid: String,
    pub(super) private_key: String,
    pub(super) public_key: String,
    pub(super) created_at: String,
    pub(super) expires_at: String,
    pub(super) is_active: bool,
}

#[derive(FromRow)]
pub(super) struct ClientRecord {
    pub(super) client_id: String,
    pub(super) created_at: String,
    pub(super) updated_at: String,
    pub(super) device_token: String,
    pub(super) device_jwt_issued_at: String,
    pub(super) public_keys: String,
    pub(super) default_kid: String,
    pub(super) gpg_keys: String,
}

#[derive(FromRow)]
pub(super) struct PairingRecord {
    pub(super) pairing_id: String,
    pub(super) expired: String,
    pub(super) client_id: Option<String>,
}

#[derive(FromRow)]
pub(super) struct ClientPairingRecord {
    pub(super) client_id: String,
    pub(super) pairing_id: String,
    pub(super) client_jwt_issued_at: String,
}
