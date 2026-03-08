use super::*;
use crate::test_http_server::{
    empty_response, json_response, spawn_response_sequence, spawn_single_response_server,
    sse_response,
};

#[test]
fn display_qr_produces_qr_output() {
    let mut buf = Vec::new();
    display_qr(&mut buf, "test-token-123", 120).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Pairing QR Code"));
    // QR output should contain block characters or spaces
    assert!(output.contains(' '));
}

#[test]
fn display_qr_handles_long_input() {
    let mut buf = Vec::new();
    display_qr(&mut buf, &"a".repeat(500), 60).unwrap();
}

#[tokio::test]
async fn fetch_pairing_token_handles_connection_error() {
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, "http://127.0.0.1:1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn fetch_pairing_token_parses_response() {
    let body = r#"{"pairing_token":"tok-abc","expires_in":300}"#;
    let addr = spawn_single_response_server(json_response("HTTP/1.1 200 OK", body)).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.pairing_token, "tok-abc");
    assert_eq!(resp.expires_in, 300);
}

#[tokio::test]
async fn fetch_pairing_token_returns_error_on_non_success() {
    let addr =
        spawn_single_response_server(empty_response("HTTP/1.1 500 Internal Server Error")).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("500"));
}

#[tokio::test]
async fn wait_for_paired_event_extracts_token() {
    let sse_body = concat!(
        "event: heartbeat\ndata: \n\n",
        "event: paired\n",
        "data: {\"client_jwt\":\"jwt-xyz\",\"client_id\":\"cid-123\"}\n\n",
    );
    let addr = spawn_single_response_server(sse_response(sse_body)).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
        .await
        .unwrap();
    assert_eq!(entry.client_jwt, "jwt-xyz");
    assert_eq!(entry.client_id, "cid-123");
}

#[tokio::test]
async fn wait_for_paired_event_aborts_on_401() {
    let addr = spawn_single_response_server(empty_response("HTTP/1.1 401 Unauthorized")).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("401"));
}

#[tokio::test]
async fn wait_for_paired_event_retries_on_503_then_succeeds() {
    let sse_body = "event: paired\n\
                    data: {\"client_jwt\":\"jwt-r\",\"client_id\":\"cid-r\"}\n\n";
    let addr = spawn_response_sequence(vec![
        empty_response("HTTP/1.1 503 Service Unavailable"),
        sse_response(sse_body),
    ])
    .await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
        .await
        .unwrap();
    assert_eq!(entry.client_jwt, "jwt-r");
    assert_eq!(entry.client_id, "cid-r");
}

#[test]
fn display_pairing_complete_writes_warning() {
    let mut buf = Vec::new();
    display_pairing_complete(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Pairing Complete"));
    assert!(output.contains("did not initiate this pairing"));
    assert!(output.contains("unpair"));
}

#[tokio::test]
async fn run_pairing_flow_end_to_end() {
    let pairing_body = r#"{"pairing_token":"pt-1","expires_in":60}"#;
    let sse_body = "event: paired\ndata: {\"client_jwt\":\"jwt-1\",\"client_id\":\"cid-1\"}\n\n";
    let addr = spawn_response_sequence(vec![
        json_response("HTTP/1.1 200 OK", pairing_body),
        sse_response(sse_body),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("tokens.json");
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let mut output = Vec::new();
    run_pairing_flow(&client, &format!("http://{addr}"), &token_path, &mut output)
        .await
        .unwrap();

    let entries = crate::token_store::load_tokens(&token_path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client_id, "cid-1");
    assert_eq!(entries[0].client_jwt, "jwt-1");

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Pairing QR Code"));
    assert!(output_str.contains("Pairing Complete"));
}
