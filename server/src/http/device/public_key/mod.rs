mod add;
mod delete;
mod list;

pub use add::add_public_key;
pub use delete::delete_public_key;
pub use list::list_public_keys;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddPublicKeyRequest {
    pub keys: Vec<serde_json::Value>,
    #[serde(default)]
    pub default_kid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyListResponse {
    pub keys: Vec<serde_json::Value>,
    pub default_kid: String,
}
