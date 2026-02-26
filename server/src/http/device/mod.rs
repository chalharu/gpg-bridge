mod delete;
mod refresh;
mod register;
mod update;
mod validation;

pub use delete::delete_device;
pub use refresh::refresh_device_jwt;
pub use register::register_device;
pub use update::update_device;

use serde::{Deserialize, Serialize};

/// POST /device request body.
#[derive(Debug, Deserialize)]
pub struct DeviceRegisterRequest {
    pub device_token: String,
    pub firebase_installation_id: String,
    pub public_key: PublicKeySet,
    #[serde(default)]
    pub default_kid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeySet {
    pub keys: KeysGroup,
}

#[derive(Debug, Deserialize)]
pub struct KeysGroup {
    pub sig: Vec<serde_json::Value>,
    pub enc: Vec<serde_json::Value>,
}

/// POST /device and POST /device/refresh response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub device_jwt: String,
}

/// PATCH /device request body.
#[derive(Debug, Deserialize)]
pub struct DeviceUpdateRequest {
    #[serde(default)]
    pub device_token: Option<String>,
    #[serde(default)]
    pub default_kid: Option<String>,
}

/// POST /device/refresh request body.
#[derive(Debug, Deserialize)]
pub struct DeviceRefreshRequest {
    pub device_jwt: String,
}

#[cfg(test)]
mod tests;
