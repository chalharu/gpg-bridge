use super::*;
use crate::e2e_crypto;
use crate::http::build_http_client;
use crate::sign_flow::SignFlowState;
use crate::test_http_server::{
    empty_response, spawn_response_sequence, spawn_single_response_server,
    spawn_single_response_server_with_request, sse_event, sse_headers, sse_response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn dummy_flow_state() -> SignFlowState {
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
    SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
        request_jwt_exp: 1_900_000_000,
        server_url: "http://localhost:0".to_owned(),
    }
}

fn flow_state_with_url(url: &str) -> (SignFlowState, serde_json::Value) {
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, enc_pub) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
        request_jwt_exp: 1_900_000_000,
        server_url: url.to_owned(),
    };
    (state, enc_pub)
}

fn fast_config() -> SignEventSseConfig {
    SignEventSseConfig {
        heartbeat_timeout: Duration::from_secs(2),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(200),
    }
}

fn signature_status_event(status: &str) -> String {
    sse_event("signature", &format!(r#"{{"status":"{status}"}}"#))
}

fn approved_jwe(enc_pub: &serde_json::Value, sig_bytes: &[u8]) -> String {
    let payload = serde_json::json!({ "signature": BASE64.encode(sig_bytes) });
    let plaintext = serde_json::to_vec(&payload).unwrap();
    e2e_crypto::encrypt_jwe_a256kw(enc_pub, &plaintext).unwrap()
}

fn signature_status_response(status: &str) -> String {
    sse_response(&signature_status_event(status))
}

#[tokio::test]
async fn approved_returns_decrypted_signature() {
    let (mut flow_state, enc_pub) = flow_state_with_url("http://placeholder");
    let jwe = approved_jwe(&enc_pub, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let event_data = serde_json::json!({"status": "approved", "signature": jwe});
    let addr = spawn_single_response_server(sse_response(&sse_event(
        "signature",
        &event_data.to_string(),
    )))
    .await;
    flow_state.server_url = format!("http://{addr}");

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(
        result,
        SignResult::Approved {
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    );
}

#[tokio::test]
async fn denied_status_returns_denied() {
    let (mut flow_state, _) = flow_state_with_url("http://placeholder");
    let addr = spawn_single_response_server(signature_status_response("denied")).await;
    flow_state.server_url = format!("http://{addr}");

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn unavailable_status_returns_unavailable() {
    let (mut flow_state, _) = flow_state_with_url("http://placeholder");
    let addr = spawn_single_response_server(signature_status_response("unavailable")).await;
    flow_state.server_url = format!("http://{addr}");

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Unavailable);
}

#[tokio::test]
async fn expired_status_returns_expired() {
    let addr = spawn_single_response_server(signature_status_response("expired")).await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Expired);
}

#[tokio::test]
async fn cancelled_status_returns_cancelled() {
    let addr = spawn_single_response_server(signature_status_response("cancelled")).await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Cancelled);
}

#[tokio::test]
async fn heartbeat_before_signature_is_handled() {
    let addr = spawn_single_response_server(sse_response(&format!(
        "{}{}",
        sse_event("heartbeat", "{}"),
        signature_status_event("denied"),
    )))
    .await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn expired_jwt_returns_expired_immediately() {
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let flow_state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjB9.sig".to_owned(),
        request_jwt_exp: 0,
        server_url: "http://localhost:0".to_owned(),
    };

    let client = build_http_client(Duration::from_secs(1), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Expired);
}

#[tokio::test]
async fn reconnects_on_server_error_then_succeeds() {
    let addr = spawn_response_sequence(vec![
        empty_response("HTTP/1.1 500 Internal Server Error"),
        signature_status_response("denied"),
    ])
    .await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn reconnects_on_stream_close_then_succeeds() {
    let addr = spawn_response_sequence(vec![
        sse_headers().to_owned(),
        signature_status_response("denied"),
    ])
    .await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn bearer_token_sent_in_request() {
    let (addr, server) =
        spawn_single_response_server_with_request(signature_status_response("denied")).await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();

    let request = server.await.unwrap();
    assert!(
        request.contains("GET /sign-events"),
        "must be GET /sign-events"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer"),
        "must have Bearer auth"
    );
}

#[test]
fn handle_signature_event_unknown_status_errors() {
    let flow_state = dummy_flow_state();
    let data = r#"{"status":"unknown_status"}"#;
    assert!(handle_signature_event(data, &flow_state).is_err());
}

#[test]
fn handle_signature_event_approved_missing_signature_field() {
    let flow_state = dummy_flow_state();
    let data = r#"{"status":"approved"}"#;
    assert!(handle_signature_event(data, &flow_state).is_err());
}

#[test]
fn handle_signature_event_invalid_json_errors() {
    let flow_state = dummy_flow_state();
    assert!(handle_signature_event("not json", &flow_state).is_err());
}

#[test]
fn handle_signature_event_denied() {
    let flow_state = dummy_flow_state();
    let result = handle_signature_event(r#"{"status":"denied"}"#, &flow_state).unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[test]
fn handle_signature_event_unavailable() {
    let flow_state = dummy_flow_state();
    let result = handle_signature_event(r#"{"status":"unavailable"}"#, &flow_state).unwrap();
    assert_eq!(result, SignResult::Unavailable);
}

#[test]
fn remaining_until_expiry_far_future() {
    let flow_state = dummy_flow_state();
    let remaining = remaining_until_expiry(&flow_state);
    assert!(remaining > Duration::ZERO);
}

#[test]
fn remaining_until_expiry_past_returns_zero() {
    let mut flow_state = dummy_flow_state();
    flow_state.request_jwt_exp = 0;
    assert_eq!(remaining_until_expiry(&flow_state), Duration::ZERO);
}

#[test]
fn compute_backoff_increases_with_attempts() {
    let config = SignEventSseConfig {
        heartbeat_timeout: Duration::from_secs(60),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    };
    let b0 = compute_backoff(&config, 0);
    let b3 = compute_backoff(&config, 3);
    assert!(b3 > b0, "backoff should increase with attempts");
}

#[test]
fn compute_backoff_capped_at_max() {
    let config = SignEventSseConfig {
        heartbeat_timeout: Duration::from_secs(60),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    };
    let b = compute_backoff(&config, 20);
    assert!(b <= config.max_backoff);
}

#[test]
fn default_config_values() {
    let config = SignEventSseConfig::default();
    assert_eq!(config.heartbeat_timeout, Duration::from_secs(60));
    assert_eq!(config.initial_backoff, Duration::from_secs(1));
    assert_eq!(config.max_backoff, Duration::from_secs(30));
}

#[tokio::test]
async fn retry_after_429_then_succeeds() {
    let addr = spawn_response_sequence(vec![
        empty_response("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1"),
        signature_status_response("denied"),
    ])
    .await;
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let client = build_http_client(Duration::from_secs(5), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn heartbeat_timeout_triggers_reconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    let config = SignEventSseConfig {
        heartbeat_timeout: Duration::from_millis(500),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(200),
    };

    tokio::spawn(async move {
        // First connection: send headers but no events — heartbeat timeout fires
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await.unwrap();
        socket.write_all(sse_headers().as_bytes()).await.unwrap();

        // Second connection: success with signature event
        let (mut socket2, _) = listener.accept().await.unwrap();
        let _ = socket2.read(&mut buf).await.unwrap();
        let body = format!(
            "{}event: signature\ndata: {{\"status\":\"denied\"}}\n\n",
            sse_headers(),
        );
        socket2.write_all(body.as_bytes()).await.unwrap();
        // Keep first socket alive until second is complete
        drop(socket);
    });

    let client = build_http_client(Duration::from_secs(5), "test").unwrap();
    let result = wait_for_sign_result(&client, &config, &flow_state)
        .await
        .unwrap();
    assert_eq!(result, SignResult::Denied);
}

#[tokio::test]
async fn transient_stream_retry_preserves_attempt_progression() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));
    let config = fast_config();
    let sse_url = format!("{}/sign-events", flow_state.server_url);
    let bearer = build_sse_bearer(&flow_state, &sse_url).unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await.unwrap();
        socket.write_all(sse_headers().as_bytes()).await.unwrap();
        drop(socket);
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let attempt = 3;
    let decision = evaluate_wait_decision(
        &client,
        &config,
        &flow_state,
        &sse_url,
        &bearer,
        attempt,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();

    match decision {
        WaitDecision::Retry {
            delay,
            next_attempt,
        } => {
            let expected_base = config
                .initial_backoff
                .saturating_mul(2_u32.saturating_pow(attempt.min(16)))
                .min(config.max_backoff);
            let min_expected_delay = expected_base
                .saturating_sub(Duration::from_millis(expected_base.as_millis() as u64 / 4));

            assert!(delay >= min_expected_delay);
            assert!(delay <= expected_base);
            assert_eq!(next_attempt, attempt + 1);
        }
        WaitDecision::Return(result) => {
            panic!("expected retry decision, got result: {result:?}");
        }
    }
}

#[tokio::test]
async fn decryption_failure_returns_terminal_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (flow_state, _) = flow_state_with_url(&format!("http://{addr}"));

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await.unwrap();
        // Send approved event with invalid JWE — should cause terminal error
        let event_data = serde_json::json!({"status": "approved", "signature": "invalid-jwe"});
        let body = format!(
            "{}event: signature\ndata: {}\n\n",
            sse_headers(),
            event_data,
        );
        socket.write_all(body.as_bytes()).await.unwrap();
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = wait_for_sign_result(&client, &fast_config(), &flow_state).await;
    assert!(
        result.is_err(),
        "decryption failure should be a terminal error, not a retry"
    );
}
