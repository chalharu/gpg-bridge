use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::{ClientInfo, filter_valid_pairings, verify_all_tokens};
use crate::http::auth::{load_active_signing_key, load_private_signing_jwk};
use crate::jwt::{PayloadType, RequestClaims, sign_jws};
use crate::repository::{AuditLogRow, CreateRequestRow};

use super::types::{
    E2eKeyItem, MAX_PENDING_REQUESTS_PER_PAIRING, SignRequestBody, SignRequestResponse,
};
use super::validation::{validate_daemon_enc_key, validate_daemon_signing_key};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn post_sign_request(
    State(state): State<AppState>,
    Json(body): Json<SignRequestBody>,
) -> Result<impl IntoResponse, AppError> {
    let clients = authenticate_clients(&body.client_jwts, &state).await?;
    validate_daemon_signing_key(&body.daemon_public_key)?;
    validate_daemon_enc_key(&body.daemon_enc_public_key)?;
    check_rate_limits(&clients, &state).await?;

    let request_id = Uuid::new_v4().to_string();
    let e2e_keys = collect_e2e_keys(&clients, &state).await;
    if e2e_keys.is_empty() {
        return Err(AppError::internal(
            "no usable E2E encryption keys found for authenticated clients",
        ));
    }
    let e2e_kids = build_e2e_kids_map(&e2e_keys);

    let request_jwt = issue_request_jwt(&request_id, &state).await?;
    let expired = compute_expiry(state.request_jwt_validity_seconds);

    persist_request(&request_id, &expired, &clients, &body, &e2e_kids, &state).await?;
    write_audit_log(&request_id, &clients, &state).await?;

    tracing::info!(request_id = %request_id, clients = clients.len(), "sign request created");

    Ok((
        StatusCode::CREATED,
        Json(SignRequestResponse {
            request_jwt,
            e2e_keys,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

async fn authenticate_clients(
    tokens: &[String],
    state: &AppState,
) -> Result<Vec<ClientInfo>, AppError> {
    if tokens.is_empty() {
        return Err(AppError::unauthorized("no client_jwts provided"));
    }
    let pairs = verify_all_tokens(tokens, state).await?;
    let filtered = filter_valid_pairings(pairs, state).await?;
    if filtered.is_empty() {
        return Err(AppError::unauthorized("all client tokens filtered out"));
    }
    Ok(filtered)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

async fn check_rate_limits(clients: &[ClientInfo], state: &AppState) -> Result<(), AppError> {
    for ci in clients {
        let count = state
            .repository
            .count_pending_requests_for_pairing(&ci.client_id, &ci.pairing_id)
            .await
            .map_err(AppError::from)?;
        if count >= MAX_PENDING_REQUESTS_PER_PAIRING {
            return Err(AppError::too_many_requests(
                "too many in-flight sign requests for this pairing",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// E2E key collection
// ---------------------------------------------------------------------------

async fn collect_e2e_keys(clients: &[ClientInfo], state: &AppState) -> Vec<E2eKeyItem> {
    let mut keys = Vec::new();
    for ci in clients {
        match lookup_enc_key(&ci.client_id, state).await {
            Some(pk) => keys.push(E2eKeyItem {
                client_id: ci.client_id.clone(),
                public_key: pk,
            }),
            None => {
                tracing::warn!(client_id = %ci.client_id, "no enc key found; skipping");
            }
        }
    }
    keys
}

async fn lookup_enc_key(client_id: &str, state: &AppState) -> Option<serde_json::Value> {
    let client = match state.repository.get_client_by_id(client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(client_id = %client_id, "failed to fetch client: {e}");
            return None;
        }
    };

    let keys: Vec<serde_json::Value> = serde_json::from_str(&client.public_keys).ok()?;
    keys.into_iter().find(|k| {
        k.get("kid").and_then(|v| v.as_str()) == Some(&client.default_kid)
            && k.get("use").and_then(|v| v.as_str()) == Some("enc")
    })
}

pub(super) fn build_e2e_kids_map(e2e_keys: &[E2eKeyItem]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for item in e2e_keys {
        if let Some(kid) = item.public_key.get("kid").and_then(|v| v.as_str()) {
            map.insert(
                item.client_id.clone(),
                serde_json::Value::String(kid.into()),
            );
        }
    }
    serde_json::Value::Object(map)
}

// ---------------------------------------------------------------------------
// JWT issuance
// ---------------------------------------------------------------------------

async fn issue_request_jwt(request_id: &str, state: &AppState) -> Result<String, AppError> {
    let signing_key = load_active_signing_key(state).await?;
    let private_jwk = load_private_signing_jwk(
        &signing_key,
        &state.signing_key_secret,
        "key decrypt failed",
        "invalid JWK",
    )?;

    let exp = chrono::Utc::now().timestamp() + state.request_jwt_validity_seconds as i64;
    let claims = RequestClaims {
        sub: request_id.to_owned(),
        payload_type: PayloadType::Request,
        exp,
    };
    sign_jws(&claims, &private_jwk, &signing_key.kid)
        .map_err(|e| AppError::internal(format!("JWS signing failed: {e}")))
}

pub(super) fn compute_expiry(validity_seconds: u64) -> String {
    let exp = chrono::Utc::now() + chrono::Duration::seconds(validity_seconds as i64);
    exp.to_rfc3339()
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

async fn persist_request(
    request_id: &str,
    expired: &str,
    clients: &[ClientInfo],
    body: &SignRequestBody,
    e2e_kids: &serde_json::Value,
    state: &AppState,
) -> Result<(), AppError> {
    let client_ids: Vec<&str> = clients.iter().map(|c| c.client_id.as_str()).collect();
    let pairing_ids = build_pairing_ids_map(clients);

    let row = CreateRequestRow {
        request_id: request_id.to_owned(),
        status: "created".to_owned(),
        expired: expired.to_owned(),
        client_ids: to_json(&client_ids)?,
        daemon_public_key: to_json(&body.daemon_public_key)?,
        daemon_enc_public_key: to_json(&body.daemon_enc_public_key)?,
        pairing_ids: to_json(&pairing_ids)?,
        e2e_kids: to_json(e2e_kids)?,
        unavailable_client_ids: "[]".to_owned(),
    };
    state
        .repository
        .create_request(&row)
        .await
        .map_err(AppError::from)
}

pub(super) fn build_pairing_ids_map(clients: &[ClientInfo]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for ci in clients {
        map.insert(
            ci.client_id.clone(),
            serde_json::Value::String(ci.pairing_id.clone()),
        );
    }
    serde_json::Value::Object(map)
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

async fn write_audit_log(
    request_id: &str,
    clients: &[ClientInfo],
    state: &AppState,
) -> Result<(), AppError> {
    let client_ids: Vec<&str> = clients.iter().map(|c| c.client_id.as_str()).collect();
    let row = AuditLogRow {
        log_id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "sign_request_created".to_owned(),
        request_id: request_id.to_owned(),
        request_ip: None,
        target_client_ids: Some(to_json(&client_ids)?),
        responding_client_id: None,
        error_code: None,
        error_message: None,
    };
    state
        .repository
        .create_audit_log(&row)
        .await
        .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// JSON serialization helper
// ---------------------------------------------------------------------------

fn to_json<T: Serialize>(value: &T) -> Result<String, AppError> {
    serde_json::to_string(value)
        .map_err(|e| AppError::internal(format!("serialization error: {e}")))
}
