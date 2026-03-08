use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::{PublicKeyListResponse, load_client_public_keys};

// ---------------------------------------------------------------------------
// GET /device/public_key
// ---------------------------------------------------------------------------

pub async fn list_public_keys(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    let (client, keys) = load_client_public_keys(&state, &auth.client_id).await?;

    Ok(Json(PublicKeyListResponse {
        keys,
        default_kid: client.default_kid,
    }))
}
