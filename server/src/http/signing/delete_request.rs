use std::collections::HashSet;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;
use uuid::Uuid;

use crate::error::AppError;
use crate::http::AppState;
use crate::http::auth::DaemonAuthJws;
use crate::repository::AuditLogRow;

use super::notifier::SignEventData;

const INSTANCE: &str = "/sign-request";

// ---------------------------------------------------------------------------
// DELETE /sign-request
// ---------------------------------------------------------------------------

pub async fn delete_sign_request(
    State(state): State<AppState>,
    auth: DaemonAuthJws,
) -> Result<impl IntoResponse, AppError> {
    let request = state
        .repository
        .get_full_request_by_id(&auth.request_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?
        .ok_or_else(|| {
            AppError::not_found("request not found or already deleted").with_instance(INSTANCE)
        })?;

    match request.status.as_str() {
        "approved" | "denied" | "unavailable" => {
            return Err(
                AppError::conflict("request already completed, cannot cancel")
                    .with_instance(INSTANCE),
            );
        }
        "created" | "pending" => {} // proceed
        _ => {
            return Err(AppError::conflict("request in unexpected state").with_instance(INSTANCE));
        }
    }

    // For pending status with encrypted_payloads: send FCM cancel to all devices
    if request.status == "pending" && request.encrypted_payloads.is_some() {
        send_cancel_to_all(
            &state,
            &auth.request_id,
            &request.client_ids,
            &request.unavailable_client_ids,
        )
        .await;
    }

    // SSE cancelled event to connected daemon
    state.sign_event_notifier.notify(
        &auth.request_id,
        SignEventData {
            signature: None,
            status: "cancelled".to_owned(),
        },
    );

    // Delete the request record from DB
    state
        .repository
        .delete_request(&auth.request_id)
        .await
        .map_err(|e| AppError::from(e).with_instance(INSTANCE))?;

    // Audit log: sign_cancelled
    write_audit_log(&state, &auth.request_id, "sign_cancelled").await;

    tracing::info!(
        request_id = %auth.request_id,
        "sign request cancelled"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// FCM cancel notification
// ---------------------------------------------------------------------------

async fn send_cancel_to_all(
    state: &AppState,
    request_id: &str,
    client_ids_json: &str,
    unavailable_client_ids_json: &str,
) {
    let client_ids: Vec<String> = match serde_json::from_str(client_ids_json) {
        Ok(ids) => ids,
        Err(_) => return,
    };

    let unavailable: HashSet<String> =
        serde_json::from_str(unavailable_client_ids_json).unwrap_or_default();

    let data = json!({
        "type": "sign_request_cancelled",
        "request_id": request_id,
    });

    for client_id in &client_ids {
        if unavailable.contains(client_id) {
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

async fn write_audit_log(state: &AppState, request_id: &str, event_type: &str) {
    let row = AuditLogRow {
        log_id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: event_type.to_owned(),
        request_id: request_id.to_owned(),
        request_ip: None,
        target_client_ids: None,
        responding_client_id: None,
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
