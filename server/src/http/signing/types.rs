use serde::{Deserialize, Serialize};

pub(crate) const MAX_PENDING_REQUESTS_PER_PAIRING: i64 = 5;
pub(super) const BASE64URL_COORD_LEN: usize = 43;

#[derive(Debug, Deserialize)]
pub struct SignRequestBody {
    pub(super) client_jwts: Vec<String>,
    pub(super) daemon_public_key: DaemonKey,
    pub(super) daemon_enc_public_key: DaemonKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonKey {
    pub(super) kty: String,
    pub(super) crv: String,
    pub(super) x: String,
    pub(super) y: String,
    pub(super) alg: String,
}

#[derive(Debug, Serialize)]
pub struct SignRequestResponse {
    pub(super) request_jwt: String,
    pub(super) e2e_keys: Vec<E2eKeyItem>,
}

#[derive(Debug, Serialize)]
pub struct E2eKeyItem {
    pub(super) client_id: String,
    pub(super) public_key: serde_json::Value,
}
