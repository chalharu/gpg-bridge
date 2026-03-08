mod add;
mod delete;
mod list;

pub use add::add_public_key;
pub use delete::delete_public_key;
pub use list::list_public_keys;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::http::AppState;
use crate::repository::ClientRow;

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

pub(super) async fn load_client_public_keys(
    state: &AppState,
    client_id: &str,
) -> Result<(ClientRow, Vec<serde_json::Value>), AppError> {
    let client = state
        .repository
        .get_client_by_id(client_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("client not found"))?;
    let keys = deserialize_public_keys(&client.public_keys)?;
    Ok((client, keys))
}

pub(super) fn deserialize_public_keys(
    public_keys_json: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    serde_json::from_str(public_keys_json)
        .map_err(|e| AppError::internal(format!("invalid public_keys JSON: {e}")))
}

pub(super) async fn save_public_keys(
    state: &AppState,
    client_id: &str,
    keys: &[serde_json::Value],
    default_kid: &str,
    expected_updated_at: &str,
) -> Result<StatusCode, AppError> {
    let keys_json = serde_json::to_string(keys)
        .map_err(|e| AppError::internal(format!("failed to serialize keys: {e}")))?;
    let now = chrono::Utc::now().to_rfc3339();

    let updated = state
        .repository
        .update_client_public_keys(
            client_id,
            &keys_json,
            default_kid,
            &now,
            expected_updated_at,
        )
        .await
        .map_err(AppError::from)?;

    if !updated {
        return Err(AppError::conflict("concurrent modification, please retry"));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{body, http::StatusCode, response::IntoResponse};

    use super::deserialize_public_keys;

    #[tokio::test]
    async fn deserialize_public_keys_maps_invalid_json_to_internal_error() {
        let error = deserialize_public_keys("{").unwrap_err();
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(problem["title"], "Internal server error");
        assert!(
            problem["detail"]
                .as_str()
                .unwrap()
                .starts_with("invalid public_keys JSON:")
        );
    }
}
