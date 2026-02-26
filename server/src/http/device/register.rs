use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::error::AppError;
use crate::http::AppState;
use crate::jwt::{DeviceClaims, PayloadType, decrypt_private_key, jwk_from_json, sign_jws};
use crate::repository::ClientRow;

use super::validation::{validate_enc_key, validate_sig_key};
use super::{DeviceRegisterRequest, DeviceResponse};

pub async fn register_device(
    State(state): State<AppState>,
    Json(mut body): Json<DeviceRegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    validate_key_counts(&body)?;

    let fid = body.firebase_installation_id.clone();

    if state
        .repository
        .client_exists(&fid)
        .await
        .map_err(AppError::from)?
    {
        return Err(AppError::conflict(
            "firebase_installation_id already registered",
        ));
    }

    check_device_token_available(&state, &body.device_token, &fid).await?;
    validate_fcm_token(&state, &body.device_token).await?;

    let enc_kids = validate_and_collect_keys(&mut body)?;
    let default_kid = resolve_default_kid(&body, &enc_kids)?;
    let public_keys = build_public_keys_json(&body)?;

    let now = chrono::Utc::now();
    let device_jwt = issue_device_jwt(&state, &fid, now).await?;
    let client = build_client_row(&fid, &body.device_token, &now, &public_keys, &default_kid);

    state
        .repository
        .create_client(&client)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::CREATED, Json(DeviceResponse { device_jwt })))
}

fn validate_key_counts(body: &DeviceRegisterRequest) -> Result<(), AppError> {
    if body.public_key.keys.sig.is_empty() {
        return Err(AppError::validation("at least one sig key is required"));
    }
    if body.public_key.keys.enc.is_empty() {
        return Err(AppError::validation("at least one enc key is required"));
    }
    Ok(())
}

pub(super) async fn check_device_token_available(
    state: &AppState,
    device_token: &str,
    fid: &str,
) -> Result<(), AppError> {
    if state
        .repository
        .client_by_device_token(device_token)
        .await
        .map_err(AppError::from)?
        .is_some_and(|existing| existing.client_id != fid)
    {
        return Err(AppError::conflict(
            "device_token already in use by another device",
        ));
    }
    Ok(())
}

async fn validate_fcm_token(state: &AppState, device_token: &str) -> Result<(), AppError> {
    let valid = state
        .fcm_validator
        .validate_token(device_token)
        .await
        .map_err(|e| AppError::internal(format!("FCM validation failed: {e}")))?;
    if !valid {
        return Err(AppError::validation("invalid device_token"));
    }
    Ok(())
}

fn validate_and_collect_keys(body: &mut DeviceRegisterRequest) -> Result<Vec<String>, AppError> {
    for key in &mut body.public_key.keys.sig {
        validate_sig_key(key)?;
    }
    let mut enc_kids = Vec::new();
    for key in &mut body.public_key.keys.enc {
        let kid = validate_enc_key(key)?;
        enc_kids.push(kid);
    }
    Ok(enc_kids)
}

fn resolve_default_kid(
    body: &DeviceRegisterRequest,
    enc_kids: &[String],
) -> Result<String, AppError> {
    let default_kid = body
        .default_kid
        .clone()
        .unwrap_or_else(|| enc_kids[0].clone());
    if !enc_kids.iter().any(|k| k == &default_kid) {
        return Err(AppError::validation(
            "default_kid must match an enc key's kid",
        ));
    }
    Ok(default_kid)
}

fn build_public_keys_json(body: &DeviceRegisterRequest) -> Result<String, AppError> {
    let mut all_keys: Vec<serde_json::Value> = Vec::new();
    all_keys.extend(body.public_key.keys.sig.iter().cloned());
    all_keys.extend(body.public_key.keys.enc.iter().cloned());
    serde_json::to_string(&all_keys)
        .map_err(|e| AppError::internal(format!("failed to serialize keys: {e}")))
}

pub(super) async fn issue_device_jwt(
    state: &AppState,
    sub: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<String, AppError> {
    let signing_key = state
        .repository
        .get_active_signing_key()
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::internal("no active signing key"))?;

    let private_json = decrypt_private_key(&signing_key.private_key, &state.signing_key_secret)
        .map_err(|e| AppError::internal(format!("failed to decrypt signing key: {e}")))?;
    let private_jwk = jwk_from_json(&private_json)
        .map_err(|e| AppError::internal(format!("failed to parse signing key: {e}")))?;

    let exp = now.timestamp() + state.device_jwt_validity_seconds as i64;
    let claims = DeviceClaims {
        sub: sub.to_owned(),
        payload_type: PayloadType::Device,
        exp,
    };

    sign_jws(&claims, &private_jwk, &signing_key.kid)
        .map_err(|e| AppError::internal(format!("failed to sign device_jwt: {e}")))
}

fn build_client_row(
    fid: &str,
    device_token: &str,
    now: &chrono::DateTime<chrono::Utc>,
    public_keys: &str,
    default_kid: &str,
) -> ClientRow {
    let ts = now.to_rfc3339();
    ClientRow {
        client_id: fid.to_owned(),
        created_at: ts.clone(),
        updated_at: ts.clone(),
        device_token: device_token.to_owned(),
        device_jwt_issued_at: ts,
        public_keys: public_keys.to_owned(),
        default_kid: default_kid.to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}
