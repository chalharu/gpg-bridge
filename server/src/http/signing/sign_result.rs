use std::collections::HashSet;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::SignJwtAuth;
use crate::repository::AuditLogRow;

use super::types::SignResultBody;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn post_sign_result(
    State(state): State<AppState>,
    auth: SignJwtAuth,
    Json(body): Json<SignResultBody>,
) -> Result<impl IntoResponse, AppError> {
    match body.status.as_str() {
        "approved" => handle_approved(&state, &auth, &body).await,
        "denied" => handle_denied(&state, &auth).await,
        "unavailable" => handle_unavailable(&state, &auth).await,
        _ => Err(AppError::validation(format!(
            "invalid status: '{}', expected 'approved', 'denied', or 'unavailable'",
            body.status
        ))),
    }
}

// ---------------------------------------------------------------------------
// Approved
// ---------------------------------------------------------------------------

async fn handle_approved(
    state: &AppState,
    auth: &SignJwtAuth,
    body: &SignResultBody,
) -> Result<StatusCode, AppError> {
    let signature = body
        .signature
        .as_ref()
        .ok_or_else(|| AppError::validation("signature is required when status is 'approved'"))?;

    let updated = state
        .repository
        .update_request_approved(&auth.request_id, signature)
        .await
        .map_err(AppError::from)?;

    if !updated {
        write_audit_log(
            state,
            &auth.request_id,
            "sign_result_conflict",
            Some(&auth.client_id),
        )
        .await;
        return Err(AppError::conflict("request status already changed"));
    }

    // Send FCM cancel to other devices
    send_cancel_to_others(state, &auth.request_id, &auth.client_id).await;

    // TODO: SSE push to daemon (KAN-30)

    write_audit_log(
        state,
        &auth.request_id,
        "sign_approved",
        Some(&auth.client_id),
    )
    .await;

    tracing::info!(
        request_id = %auth.request_id,
        client_id = %auth.client_id,
        "sign request approved"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Denied
// ---------------------------------------------------------------------------

async fn handle_denied(state: &AppState, auth: &SignJwtAuth) -> Result<StatusCode, AppError> {
    let updated = state
        .repository
        .update_request_denied(&auth.request_id)
        .await
        .map_err(AppError::from)?;

    if !updated {
        write_audit_log(
            state,
            &auth.request_id,
            "sign_result_conflict",
            Some(&auth.client_id),
        )
        .await;
        return Err(AppError::conflict("request status already changed"));
    }

    // Send FCM cancel to other devices
    send_cancel_to_others(state, &auth.request_id, &auth.client_id).await;

    // TODO: SSE push to daemon (KAN-30)

    write_audit_log(
        state,
        &auth.request_id,
        "sign_denied",
        Some(&auth.client_id),
    )
    .await;

    tracing::info!(
        request_id = %auth.request_id,
        client_id = %auth.client_id,
        "sign request denied"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Unavailable
// ---------------------------------------------------------------------------

async fn handle_unavailable(state: &AppState, auth: &SignJwtAuth) -> Result<StatusCode, AppError> {
    let result = state
        .repository
        .add_unavailable_client_id(&auth.request_id, &auth.client_id)
        .await
        .map_err(AppError::from)?;

    let (updated_unavailable, client_ids_json) = match result {
        Some(pair) => pair,
        None => {
            return Err(AppError::conflict(
                "client already marked as unavailable or request status changed",
            ));
        }
    };

    write_audit_log(
        state,
        &auth.request_id,
        "sign_device_unavailable",
        Some(&auth.client_id),
    )
    .await;

    // Check if ALL client_ids are now unavailable
    let client_ids: Vec<String> = serde_json::from_str(&client_ids_json)
        .map_err(|e| AppError::internal(format!("invalid client_ids: {e}")))?;
    let unavailable: Vec<String> = serde_json::from_str(&updated_unavailable)
        .map_err(|e| AppError::internal(format!("invalid unavailable_client_ids: {e}")))?;

    let all_unavailable = client_ids.iter().all(|cid| unavailable.contains(cid));

    if all_unavailable {
        let status_updated = state
            .repository
            .update_request_unavailable(&auth.request_id)
            .await
            .map_err(AppError::from)?;

        if status_updated {
            // TODO: SSE push to daemon (KAN-30)
            // No FCM cancel needed: all clients already responded unavailable
            write_audit_log(state, &auth.request_id, "sign_unavailable", None).await;
            tracing::info!(request_id = %auth.request_id, "all devices unavailable");
        }
    }

    tracing::info!(
        request_id = %auth.request_id,
        client_id = %auth.client_id,
        "device marked unavailable"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// FCM notifications
// ---------------------------------------------------------------------------

async fn send_cancel_to_others(state: &AppState, request_id: &str, responding_client_id: &str) {
    let request = match state.repository.get_full_request_by_id(request_id).await {
        Ok(Some(r)) => r,
        _ => return,
    };

    let client_ids: Vec<String> = match serde_json::from_str(&request.client_ids) {
        Ok(ids) => ids,
        Err(_) => return,
    };

    // Parse unavailable_client_ids to exclude already-responded devices
    let unavailable: HashSet<String> =
        serde_json::from_str(&request.unavailable_client_ids).unwrap_or_default();

    let data = json!({
        "type": "sign_request_cancelled",
        "request_id": request_id,
    });

    for client_id in &client_ids {
        // Skip the responding device and already-unavailable devices
        if client_id == responding_client_id || unavailable.contains(client_id) {
            continue;
        }
        let token = match super::helpers::lookup_device_token(client_id, state).await {
            Some(t) => t,
            None => continue,
        };
        if let Err(e) = state.fcm_sender.send_data_message(&token, &data).await {
            tracing::warn!(client_id = %client_id, "FCM cancel failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

async fn write_audit_log(
    state: &AppState,
    request_id: &str,
    event_type: &str,
    responding_client_id: Option<&str>,
) {
    let row = AuditLogRow {
        log_id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: event_type.to_owned(),
        request_id: request_id.to_owned(),
        request_ip: None,
        target_client_ids: None,
        responding_client_id: responding_client_id.map(|s| s.to_owned()),
        error_code: None,
        error_message: None,
    };
    if let Err(e) = state.repository.create_audit_log(&row).await {
        tracing::error!(
            request_id = %request_id,
            event_type = %event_type,
            "audit log write failed: {e:?}"
        );
    }
}
