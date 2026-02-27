mod add;
mod delete;
mod list;

pub use add::add_gpg_key;
pub use delete::delete_gpg_key;
pub use list::list_gpg_keys;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GpgKeyRegisterRequest {
    pub gpg_keys: Vec<GpgKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgKeyEntry {
    pub keygrip: String,
    pub key_id: String,
    pub public_key: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct GpgKeyListResponse {
    pub gpg_keys: Vec<GpgKeyEntry>,
}
