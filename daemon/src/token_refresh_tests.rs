use super::*;
use crate::test_http_server::{
    empty_response, json_response, spawn_response_sequence, spawn_single_response_server,
};

fn test_http_client(timeout: std::time::Duration) -> Client {
    Client::builder().timeout(timeout).build().unwrap()
}

#[test]
fn decode_jws_payload_parses_valid_jwt() {
    let jwt = build_test_jwt(1000, 2000);
    let payload = decode_jws_payload(&jwt).unwrap();
    assert_eq!(payload.iat, Some(1000));
    assert_eq!(payload.exp, Some(2000));
}

#[test]
fn decode_jws_payload_rejects_invalid_segment_count() {
    let result = decode_jws_payload("only.two");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("3 segments"));
}

#[test]
fn decode_jws_payload_rejects_invalid_base64() {
    let result = decode_jws_payload("a.!!!.c");
    assert!(result.is_err());
}

#[test]
fn needs_refresh_returns_true_when_near_expiry() {
    // Total lifetime = 900s, if remaining < 300s then needs refresh.
    // Set iat = now - 700, exp = now + 200 => remaining = 200 < 300
    let now = current_unix_timestamp();
    let jwt = build_test_jwt(now - 700, now + 200);
    assert!(needs_refresh(&jwt));
}

#[test]
fn needs_refresh_returns_false_when_well_within_validity() {
    // Total lifetime = 900s, remaining = 800 => 800 >= 300
    let now = current_unix_timestamp();
    let jwt = build_test_jwt(now - 100, now + 800);
    assert!(!needs_refresh(&jwt));
}

#[test]
fn needs_refresh_returns_true_when_expired() {
    let now = current_unix_timestamp();
    let jwt = build_test_jwt(now - 1000, now - 1);
    assert!(needs_refresh(&jwt));
}

#[test]
fn needs_refresh_returns_false_without_exp() {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
    let payload = URL_SAFE_NO_PAD.encode(b"{\"iat\":1000}");
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    let jwt = format!("{header}.{payload}.{sig}");
    assert!(!needs_refresh(&jwt));
}

#[test]
fn needs_refresh_returns_false_without_iat() {
    let now = current_unix_timestamp();
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
    let payload_json = format!("{{\"exp\":{}}}", now + 1000);
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    let jwt = format!("{header}.{payload}.{sig}");
    assert!(!needs_refresh(&jwt));
}

#[test]
fn needs_refresh_returns_false_for_invalid_jwt() {
    assert!(!needs_refresh("not-a-jwt"));
}

#[test]
fn needs_refresh_returns_false_when_exp_lte_iat() {
    let jwt = build_test_jwt(2000, 1000);
    assert!(!needs_refresh(&jwt));
}

#[tokio::test]
async fn refresh_token_handles_connection_error() {
    let client = test_http_client(std::time::Duration::from_millis(100));
    let result = refresh_token(&client, "http://127.0.0.1:1", "jwt").await;
    assert!(matches!(result, Err(TokenRefreshError::Other(_))));
}

#[tokio::test]
async fn refresh_token_returns_re_pairing_on_401() {
    let addr = spawn_single_response_server(empty_response("HTTP/1.1 401 Unauthorized")).await;

    let client = test_http_client(std::time::Duration::from_secs(2));
    let result = refresh_token(&client, &format!("http://{addr}"), "old-jwt").await;
    assert!(matches!(
        result,
        Err(TokenRefreshError::RePairingRequired { .. })
    ));
}

#[tokio::test]
async fn refresh_token_returns_re_pairing_on_404() {
    let addr = spawn_single_response_server(empty_response("HTTP/1.1 404 Not Found")).await;

    let client = test_http_client(std::time::Duration::from_secs(2));
    let result = refresh_token(&client, &format!("http://{addr}"), "old-jwt").await;
    assert!(matches!(
        result,
        Err(TokenRefreshError::RePairingRequired { .. })
    ));
}

#[tokio::test]
async fn refresh_token_parses_new_jwt() {
    let body = r#"{"client_jwt":"new-jwt-value"}"#;
    let addr = spawn_single_response_server(json_response("HTTP/1.1 200 OK", body)).await;

    let client = test_http_client(std::time::Duration::from_secs(2));
    let new_jwt = refresh_token(&client, &format!("http://{addr}"), "old-jwt")
        .await
        .unwrap();
    assert_eq!(new_jwt, "new-jwt-value");
}

#[tokio::test]
async fn check_and_refresh_all_skips_when_no_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    let client = Client::new();
    let summary = check_and_refresh_all(&client, "http://unused", &path)
        .await
        .unwrap();
    assert!(summary.re_pairing_needed.is_empty());
}

#[tokio::test]
async fn check_and_refresh_all_refreshes_expired_token() {
    use crate::token_store::{TokenEntry, save_tokens};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");

    // Create a token that is nearly expired
    let now = current_unix_timestamp();
    let old_jwt = build_test_jwt(now - 900, now + 50);

    save_tokens(
        &path,
        &[TokenEntry {
            client_jwt: old_jwt,
            client_id: "cid-1".into(),
        }],
    )
    .unwrap();

    let body = r#"{"client_jwt":"refreshed-jwt"}"#;
    let addr = spawn_single_response_server(json_response("HTTP/1.1 200 OK", body)).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let summary = check_and_refresh_all(&client, &format!("http://{addr}"), &path)
        .await
        .unwrap();

    assert!(summary.re_pairing_needed.is_empty());
    let entries = load_tokens(&path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client_jwt, "refreshed-jwt");
}

#[tokio::test]
async fn check_and_refresh_all_reports_re_pairing_needed() {
    use crate::token_store::{TokenEntry, save_tokens};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    let now = current_unix_timestamp();
    let old_jwt = build_test_jwt(now - 900, now + 50);

    save_tokens(
        &path,
        &[TokenEntry {
            client_jwt: old_jwt,
            client_id: "cid-repa".into(),
        }],
    )
    .unwrap();

    let addr = spawn_response_sequence(vec![empty_response("HTTP/1.1 401 Unauthorized")]).await;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let summary = check_and_refresh_all(&client, &format!("http://{addr}"), &path)
        .await
        .unwrap();

    assert_eq!(summary.re_pairing_needed, vec!["cid-repa"]);
}
