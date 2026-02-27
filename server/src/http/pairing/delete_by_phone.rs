use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

use super::helpers::{remove_pairing_and_cleanup, verify_pairing_ownership};

// ---------------------------------------------------------------------------
// DELETE /pairing/{pairing_id}
// ---------------------------------------------------------------------------

pub async fn delete_pairing_by_phone(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
    Path(pairing_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let instance = "/pairing/{pairing_id}";

    verify_pairing_ownership(&state, &auth.client_id, &pairing_id, instance).await?;
    remove_pairing_and_cleanup(&state, &auth.client_id, &pairing_id, instance).await?;

    Ok(StatusCode::NO_CONTENT)
}
