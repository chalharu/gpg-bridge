use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DeviceAssertionAuth;

pub async fn delete_device(
    State(state): State<AppState>,
    auth: DeviceAssertionAuth,
) -> Result<impl IntoResponse, AppError> {
    state
        .repository
        .delete_client(&auth.client_id)
        .await
        .map_err(AppError::from)?;

    Ok(StatusCode::NO_CONTENT)
}
