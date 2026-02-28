use crate::http::AppState;

pub(super) async fn lookup_device_token(client_id: &str, state: &AppState) -> Option<String> {
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
