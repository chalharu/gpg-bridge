use axum::{Json, extract::State, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::GpgKeyListResponse;
use super::add::load_client_gpg_keys;

// ---------------------------------------------------------------------------
// GET /device/gpg_key
// ---------------------------------------------------------------------------

pub async fn list_gpg_keys(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    let (_, gpg_keys) = load_client_gpg_keys(&state, &auth.client_id).await?;

    Ok(Json(GpgKeyListResponse { gpg_keys }))
}
