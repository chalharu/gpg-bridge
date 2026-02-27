use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{PairingClaims, PayloadType, decrypt_private_key, jwk_from_json, sign_jws};
use crate::repository::SigningKeyRow;

// ---------------------------------------------------------------------------
// GET /pairing-token
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PairingTokenResponse {
    pub pairing_token: String,
    pub expires_in: u64,
}

pub async fn get_pairing_token(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    check_unconsumed_limit(&state).await?;
    let signing_key = fetch_active_signing_key(&state).await?;
    let (pairing_id, exp) = create_pairing_record(&state).await?;
    let pairing_token = sign_pairing_token(&state, &signing_key, &pairing_id, exp)?;

    Ok(Json(PairingTokenResponse {
        pairing_token,
        expires_in: state.pairing_jwt_validity_seconds,
    }))
}

async fn check_unconsumed_limit(state: &AppState) -> Result<(), AppError> {
    let now_str = chrono::Utc::now().to_rfc3339();
    let count = state
        .repository
        .count_unconsumed_pairings(&now_str)
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing-token"))?;

    if count >= state.unconsumed_pairing_limit {
        return Err(
            AppError::too_many_requests("unconsumed pairing limit reached")
                .with_instance("/pairing-token"),
        );
    }
    Ok(())
}

async fn fetch_active_signing_key(state: &AppState) -> Result<SigningKeyRow, AppError> {
    state
        .repository
        .get_active_signing_key()
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing-token"))?
        .ok_or_else(|| AppError::internal("no active signing key").with_instance("/pairing-token"))
}

async fn create_pairing_record(
    state: &AppState,
) -> Result<(String, chrono::DateTime<chrono::Utc>), AppError> {
    let pairing_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::seconds(state.pairing_jwt_validity_seconds as i64);

    state
        .repository
        .create_pairing(&pairing_id, &exp.to_rfc3339())
        .await
        .map_err(|e| AppError::from(e).with_instance("/pairing-token"))?;

    Ok((pairing_id, exp))
}

fn sign_pairing_token(
    state: &AppState,
    signing_key: &SigningKeyRow,
    pairing_id: &str,
    exp: chrono::DateTime<chrono::Utc>,
) -> Result<String, AppError> {
    let private_json = decrypt_private_key(&signing_key.private_key, &state.signing_key_secret)
        .map_err(|e| {
            tracing::error!("key decrypt failed: {e}");
            AppError::internal("internal server error").with_instance("/pairing-token")
        })?;
    let private_jwk = jwk_from_json(&private_json).map_err(|e| {
        tracing::error!("invalid private JWK: {e}");
        AppError::internal("internal server error").with_instance("/pairing-token")
    })?;

    let claims = PairingClaims {
        sub: pairing_id.to_owned(),
        payload_type: PayloadType::Pairing,
        exp: exp.timestamp(),
    };
    sign_jws(&claims, &private_jwk, &signing_key.kid).map_err(|e| {
        tracing::error!("JWS signing failed: {e}");
        AppError::internal("internal server error").with_instance("/pairing-token")
    })
}
