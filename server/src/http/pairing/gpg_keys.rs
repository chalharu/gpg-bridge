use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::ClientJwtAuth;
use crate::http::device::GpgKeyEntry;

// ---------------------------------------------------------------------------
// POST /pairing/gpg-keys
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PairingGpgKeyEntry {
    #[serde(flatten)]
    pub entry: GpgKeyEntry,
    pub client_id: String,
}

#[derive(Debug, Serialize)]
pub struct PairingGpgKeysResponse {
    pub gpg_keys: Vec<PairingGpgKeyEntry>,
}

pub async fn query_gpg_keys(
    State(state): State<AppState>,
    auth: ClientJwtAuth,
) -> Result<impl IntoResponse, AppError> {
    let mut result = Vec::new();

    for client_info in &auth.clients {
        let client = state
            .repository
            .get_client_by_id(&client_info.client_id)
            .await
            .map_err(AppError::from)?;

        if let Some(client) = client {
            let keys: Vec<GpgKeyEntry> = serde_json::from_str(&client.gpg_keys)
                .map_err(|e| AppError::internal(format!("invalid gpg_keys JSON: {e}")))?;

            for key in keys {
                result.push(PairingGpgKeyEntry {
                    entry: key,
                    client_id: client_info.client_id.clone(),
                });
            }
        } else {
            tracing::warn!(client_id = %client_info.client_id, "verified client not found in database");
        }
    }

    Ok(Json(PairingGpgKeysResponse { gpg_keys: result }))
}
