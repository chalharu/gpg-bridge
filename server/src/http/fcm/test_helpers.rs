use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::http::fcm::client::FcmClient;
use crate::http::fcm::oauth2::ServiceAccountKey;

pub fn test_service_account() -> ServiceAccountKey {
    ServiceAccountKey {
        client_email: "test@proj.iam.gserviceaccount.com".to_owned(),
        private_key: include_str!("../../../test_fixtures/fake_rsa_key.pem").to_owned(),
        token_uri: None,
    }
}

/// Shared state for the mock server to track received requests.
#[derive(Debug, Clone, Default)]
pub struct MockState {
    pub token_calls: Arc<Mutex<Vec<String>>>,
    pub fcm_calls: Arc<Mutex<Vec<Value>>>,
    pub fcm_response_status: Arc<Mutex<StatusCode>>,
    pub fcm_response_body: Arc<Mutex<Value>>,
}

pub async fn mock_token_handler(
    State(state): State<MockState>,
    body: String,
) -> (StatusCode, Json<Value>) {
    state.token_calls.lock().await.push(body);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": "mock-access-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        })),
    )
}

pub async fn mock_fcm_handler(
    State(state): State<MockState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.fcm_calls.lock().await.push(body);
    let status = *state.fcm_response_status.lock().await;
    let body = state.fcm_response_body.lock().await.clone();
    (status, Json(body))
}

pub fn mock_router(state: MockState) -> Router {
    Router::new()
        .route("/token", post(mock_token_handler))
        .route(
            "/v1/projects/{project_id}/messages:send",
            post(mock_fcm_handler),
        )
        .with_state(state)
}

pub async fn start_mock_server(state: MockState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, mock_router(state)).await.unwrap();
    });
    base
}

pub fn build_test_client(base_url: &str) -> FcmClient {
    let sa = test_service_account();
    FcmClient::new("test-project".to_owned(), sa)
        .unwrap()
        .with_urls(base_url.to_owned(), format!("{base_url}/token"))
}
