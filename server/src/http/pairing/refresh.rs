use axum::Json;
use axum::extract::{FromRequest, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::verify_one_token;
use crate::jwt::extract_kid;
use crate::repository::SigningKeyRow;

use super::helpers::{build_client_jwt_token, verify_pairing_ownership};

// ---------------------------------------------------------------------------
// POST /pairing/refresh
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub client_jwt: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub client_jwt: String,
}

pub async fn refresh_client_jwt(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse, AppError> {
    let Json(body) = Json::<RefreshRequest>::from_request(req, &state)
        .await
        .map_err(|e| AppError::validation(format!("invalid request body: {e}")))?;
    let (client_id, pairing_id) = verify_one_token(&body.client_jwt, &state)
        .await
        .map_err(|e| e.with_instance("/pairing/refresh"))?;

    verify_pairing_ownership(&state, &client_id, &pairing_id, "/pairing/refresh").await?;

    let signing_key = fetch_signing_key_from_jwt(&body.client_jwt, &state).await?;
    let new_jwt = build_client_jwt_token(&state, &signing_key, &client_id, &pairing_id)?;
    update_issued_at(&state, &client_id, &pairing_id).await?;

    Ok(Json(RefreshResponse {
        client_jwt: new_jwt,
    }))
}

/// Extract the kid from the old JWT and fetch its signing key.
async fn fetch_signing_key_from_jwt(
    jwt: &str,
    state: &AppState,
) -> Result<SigningKeyRow, AppError> {
    let kid = extract_kid(jwt).map_err(|e| {
        tracing::error!("kid extraction failed: {e}");
        AppError::internal("internal server error")
    })?;

    state
        .repository
        .get_signing_key_by_kid(&kid)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing/refresh"))?
        .ok_or_else(|| {
            AppError::internal("signing key not found").with_instance("/pairing/refresh")
        })
}

async fn update_issued_at(
    state: &AppState,
    client_id: &str,
    pairing_id: &str,
) -> Result<(), AppError> {
    let now_str = chrono::Utc::now().to_rfc3339();
    let updated = state
        .repository
        .update_client_jwt_issued_at(client_id, pairing_id, &now_str)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing/refresh"))?;
    if !updated {
        return Err(
            AppError::not_found("client pairing not found").with_instance("/pairing/refresh")
        );
    }
    Ok(())
}
