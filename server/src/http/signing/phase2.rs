use std::collections::HashSet;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DaemonAuthJws;
use crate::repository::AuditLogRow;

use super::types::PatchSignRequestBody;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn patch_sign_request(
    State(state): State<AppState>,
    auth: DaemonAuthJws,
    Json(body): Json<PatchSignRequestBody>,
) -> Result<impl IntoResponse, AppError> {
    let request = load_request(&auth.request_id, &state).await?;
    validate_status(&request.status)?;
    validate_payloads(&body, &request.client_ids)?;

    let payloads_json = build_payloads_json(&body)?;
    let updated = cas_update(&auth.request_id, &payloads_json, &state).await?;
    if !updated {
        return Err(AppError::conflict("request status changed concurrently"));
    }

    send_notifications(&request.client_ids, &auth.request_id, &state).await;

    if let Err(e) = write_audit_log(&auth.request_id, &request.client_ids, &state).await {
        // Audit log failure must not mask a successful CAS update.
        // The request has already transitioned to "pending", so we log
        // the failure and still return 204 to the caller.
        tracing::error!(request_id = %auth.request_id, "audit log write failed after CAS update: {e:?}");
    }

    tracing::info!(request_id = %auth.request_id, "sign request dispatched");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Request loading
// ---------------------------------------------------------------------------

async fn load_request(
    request_id: &str,
    state: &AppState,
) -> Result<crate::repository::FullRequestRow, AppError> {
    state
        .repository
        .get_full_request_by_id(request_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("request not found"))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_status(status: &str) -> Result<(), AppError> {
    if status != "created" {
        return Err(AppError::conflict(format!(
            "request status is '{status}', expected 'created'"
        )));
    }
    Ok(())
}

fn validate_payloads(body: &PatchSignRequestBody, client_ids_json: &str) -> Result<(), AppError> {
    let expected: HashSet<String> = serde_json::from_str(client_ids_json)
        .map_err(|e| AppError::internal(format!("invalid client_ids in DB: {e}")))?;
    let provided: HashSet<String> = body
        .encrypted_payloads
        .iter()
        .map(|p| p.client_id.clone())
        .collect();
    // Detect duplicate client_ids in the request body
    if provided.len() != body.encrypted_payloads.len() {
        return Err(AppError::validation(
            "encrypted_payloads contains duplicate client_ids",
        ));
    }
    if expected != provided {
        return Err(AppError::validation(
            "encrypted_payloads client_ids do not match the request",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn build_payloads_json(body: &PatchSignRequestBody) -> Result<String, AppError> {
    serde_json::to_string(&body.encrypted_payloads)
        .map_err(|e| AppError::internal(format!("serialization error: {e}")))
}

async fn cas_update(
    request_id: &str,
    payloads_json: &str,
    state: &AppState,
) -> Result<bool, AppError> {
    state
        .repository
        .update_request_phase2(request_id, payloads_json)
        .await
        .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// FCM notifications
// ---------------------------------------------------------------------------

async fn send_notifications(client_ids_json: &str, request_id: &str, state: &AppState) {
    let client_ids: Vec<String> = match serde_json::from_str(client_ids_json) {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!("failed to parse client_ids for FCM: {e}");
            return;
        }
    };
    let data = json!({
        "type": "sign_request",
        "request_id": request_id,
    });
    for client_id in &client_ids {
        let token = match lookup_device_token(client_id, state).await {
            Some(t) => t,
            None => continue,
        };
        if let Err(e) = state.fcm_sender.send_data_message(&token, &data).await {
            tracing::warn!(client_id = %client_id, "FCM send failed: {e}");
        }
    }
}

async fn lookup_device_token(client_id: &str, state: &AppState) -> Option<String> {
    match state.repository.get_client_by_id(client_id).await {
        Ok(Some(c)) => Some(c.device_token),
        Ok(None) => {
            tracing::warn!(client_id = %client_id, "client not found for FCM");
            None
        }
        Err(e) => {
            tracing::error!(client_id = %client_id, "failed to fetch client: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

async fn write_audit_log(
    request_id: &str,
    client_ids_json: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let row = AuditLogRow {
        log_id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "sign_request_dispatched".to_owned(),
        request_id: request_id.to_owned(),
        // TODO: propagate real client IP once X-Forwarded-For / ConnectInfo is wired
        request_ip: None,
        target_client_ids: Some(client_ids_json.to_owned()),
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
