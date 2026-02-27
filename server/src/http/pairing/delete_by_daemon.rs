use axum::Json;
use axum::extract::{FromRequest, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::verify_one_token;

use super::helpers::{remove_pairing_and_cleanup, verify_pairing_ownership};

// ---------------------------------------------------------------------------
// DELETE /pairing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeletePairingBody {
    pub client_jwt: String,
}

pub async fn delete_pairing_by_daemon(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse, AppError> {
    let Json(body) = Json::<DeletePairingBody>::from_request(req, &state)
        .await
        .map_err(|e| AppError::validation(format!("invalid request body: {e}")))?;
    let (client_id, pairing_id) = verify_one_token(&body.client_jwt, &state)
        .await
        .map_err(|e| e.with_instance("/pairing"))?;

    verify_pairing_ownership(&state, &client_id, &pairing_id, "/pairing").await?;
    remove_pairing_and_cleanup(&state, &client_id, &pairing_id, "/pairing").await?;

    Ok(StatusCode::NO_CONTENT)
}
