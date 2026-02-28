use axum::http::StatusCode;

use crate::http::fcm::oauth2::OAuth2TokenManager;
use crate::http::fcm::{FcmSender, FcmValidator};

use super::test_helpers::{MockState, build_test_client, start_mock_server, test_service_account};

#[tokio::test]
async fn send_data_message_success() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::OK;
    *mock.fcm_response_body.lock().await =
        serde_json::json!({"name": "projects/test/messages/123"});
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    let data = serde_json::json!({"type": "sign_request", "request_id": "abc"});
    client
        .send_data_message("device-token-1", &data)
        .await
        .unwrap();

    let calls = mock.fcm_calls.lock().await;
    assert_eq!(calls.len(), 1);
    let msg = &calls[0]["message"];
    assert_eq!(msg["token"], "device-token-1");
    assert_eq!(msg["data"]["type"], "sign_request");
    assert_eq!(msg["data"]["request_id"], "abc");
}

#[tokio::test]
async fn send_data_message_unregistered_error() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::NOT_FOUND;
    *mock.fcm_response_body.lock().await = serde_json::json!({
        "error": {
            "code": 404,
            "message": "Requested entity was not found.",
            "details": [{"errorCode": "UNREGISTERED"}]
        }
    });
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    let data = serde_json::json!({"type": "sign_request"});
    let err = client
        .send_data_message("bad-token", &data)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("UNREGISTERED"));
}

#[tokio::test]
async fn validate_token_returns_true_for_valid() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::OK;
    *mock.fcm_response_body.lock().await = serde_json::json!({"name": ""});
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    assert!(client.validate_token("good-token").await.unwrap());

    let calls = mock.fcm_calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["validate_only"], true);
}

#[tokio::test]
async fn validate_token_returns_false_for_unregistered() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::NOT_FOUND;
    *mock.fcm_response_body.lock().await = serde_json::json!({
        "error": {"code": 404, "details": [{"errorCode": "UNREGISTERED"}]}
    });
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    assert!(!client.validate_token("bad-token").await.unwrap());
}

#[tokio::test]
async fn validate_token_returns_false_for_invalid_argument() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::BAD_REQUEST;
    *mock.fcm_response_body.lock().await = serde_json::json!({
        "error": {"code": 400, "details": [{"errorCode": "INVALID_ARGUMENT"}]}
    });
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    assert!(!client.validate_token("malformed").await.unwrap());
}

#[tokio::test]
async fn validate_token_returns_error_for_server_error() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::INTERNAL_SERVER_ERROR;
    *mock.fcm_response_body.lock().await = serde_json::json!({
        "error": {"code": 500, "details": [{"errorCode": "INTERNAL"}]}
    });
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    let err = client.validate_token("token").await.unwrap_err();
    assert!(err.to_string().contains("INTERNAL"));
}

#[tokio::test]
async fn oauth2_token_included_in_request() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::OK;
    *mock.fcm_response_body.lock().await = serde_json::json!({"name": ""});
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    let data = serde_json::json!({"key": "val"});
    client.send_data_message("tok", &data).await.unwrap();

    let token_calls = mock.token_calls.lock().await;
    assert_eq!(token_calls.len(), 1);
    assert!(token_calls[0].contains("grant_type="));
    assert!(token_calls[0].contains("assertion="));
}

#[tokio::test]
async fn oauth2_token_exchange_success() {
    let mock = MockState::default();
    let base = start_mock_server(mock.clone()).await;

    let sa = test_service_account();
    let mgr =
        OAuth2TokenManager::new(sa, reqwest::Client::new()).with_endpoint(format!("{base}/token"));

    let token = mgr.get_access_token().await.unwrap();
    assert_eq!(token, "mock-access-token");
}

#[tokio::test]
async fn send_data_message_converts_non_string_values() {
    let mock = MockState::default();
    *mock.fcm_response_status.lock().await = StatusCode::OK;
    *mock.fcm_response_body.lock().await = serde_json::json!({"name": ""});
    let base = start_mock_server(mock.clone()).await;
    let client = build_test_client(&base);

    let data = serde_json::json!({"count": 42, "flag": true});
    client.send_data_message("tok", &data).await.unwrap();

    let calls = mock.fcm_calls.lock().await;
    let msg_data = &calls[0]["message"]["data"];
    assert_eq!(msg_data["count"], "42");
    assert_eq!(msg_data["flag"], "true");
}
