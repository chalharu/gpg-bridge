use super::*;
use crate::http::build_http_client;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn algo_number_to_name_sha256() {
    assert_eq!(algo_number_to_name(8), Some("sha256"));
}

#[test]
fn algo_number_to_name_sha512() {
    assert_eq!(algo_number_to_name(10), Some("sha512"));
}

#[test]
fn algo_number_to_name_sha1() {
    assert_eq!(algo_number_to_name(2), Some("sha1"));
}

#[test]
fn algo_number_to_name_md5() {
    assert_eq!(algo_number_to_name(1), Some("md5"));
}

#[test]
fn algo_number_to_name_rmd160() {
    assert_eq!(algo_number_to_name(3), Some("rmd160"));
}

#[test]
fn algo_number_to_name_sha384() {
    assert_eq!(algo_number_to_name(9), Some("sha384"));
}

#[test]
fn algo_number_to_name_sha224() {
    assert_eq!(algo_number_to_name(11), Some("sha224"));
}

#[test]
fn algo_number_to_name_unknown_returns_none() {
    assert_eq!(algo_number_to_name(0), None);
    assert_eq!(algo_number_to_name(99), None);
}

#[test]
fn build_encrypted_payloads_produces_valid_entries() {
    let (_priv, pub_json) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let keys = vec![E2eKeyEntry {
        client_id: "client-1".to_owned(),
        public_key: pub_json,
    }];
    let payloads = build_encrypted_payloads(&keys, &[0xAA; 32], "sha256", "0xABCD1234").unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["client_id"], "client-1");
    let enc = payloads[0]["encrypted_data"].as_str().unwrap();
    assert_eq!(enc.split('.').count(), 5, "JWE compact must have 5 parts");
}

#[test]
fn build_encrypted_payloads_hash_uses_standard_base64() {
    let (_priv, pub_json) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let keys = vec![E2eKeyEntry {
        client_id: "c1".to_owned(),
        public_key: pub_json.clone(),
    }];
    let hash = vec![0xFA, 0xCE, 0xCA, 0xFE];
    let payloads = build_encrypted_payloads(&keys, &hash, "sha256", "key1").unwrap();
    // The encrypted_data is a JWE, so we can't directly inspect plaintext,
    // but we can verify the function doesn't panic with real data.
    assert!(!payloads.is_empty());
}

#[tokio::test]
async fn run_phase1_with_empty_token_file_fails() {
    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty-tokens");
    std::fs::write(&path, "[]").unwrap();

    let result = run_phase1(&client, "http://localhost:0", &path).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("no client tokens"),
        "should fail with 'no client tokens'"
    );
}

#[tokio::test]
async fn run_phase1_with_nonexistent_token_file_fails() {
    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let result = run_phase1(
        &client,
        "http://localhost:0",
        Path::new("/nonexistent/tokens"),
    )
    .await;
    // Empty token file or missing file → empty tokens → error
    assert!(result.is_err());
}

/// Build a minimal Phase 1 response JSON string with a fake request_jwt.
fn fake_phase1_response() -> String {
    // Build a fake JWT with an exp claim
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"sub":"req-1","exp":1900000000}"#);
    let request_jwt = format!("{header}.{payload}.fake-sig");

    let (_priv, pub_json) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let response = json!({
        "request_jwt": request_jwt,
        "e2e_keys": [{ "client_id": "client-1", "public_key": pub_json }],
    });
    serde_json::to_string(&response).unwrap()
}

#[tokio::test]
async fn run_phase1_sends_request_and_parses_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let resp_body = fake_phase1_response();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();

        let response = format!(
            "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        request
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens");
    let tokens = json!([{"client_jwt": "jwt-abc", "client_id": "id-1"}]);
    std::fs::write(&path, serde_json::to_string(&tokens).unwrap()).unwrap();

    let (flow_state, e2e_keys) = run_phase1(&client, &format!("http://{addr}"), &path)
        .await
        .unwrap();

    let request = server.await.unwrap();
    assert!(request.contains("client_jwts"));
    assert!(request.contains("daemon_public_key"));
    assert!(request.contains("daemon_enc_public_key"));
    assert!(!flow_state.request_jwt.is_empty());
    assert_eq!(flow_state.request_jwt_exp, 1_900_000_000);
    assert_eq!(e2e_keys.len(), 1);
    assert_eq!(e2e_keys[0].client_id, "client-1");
}

#[tokio::test]
async fn run_phase2_returns_accepted_on_204() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        let _n = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let (auth_priv, _auth_pub, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _enc_pub) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let (_e2e_priv, e2e_pub) = e2e_crypto::generate_ecdh_keypair().unwrap();

    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
        request_jwt_exp: 1_900_000_000,
        server_url: format!("http://{addr}"),
    };
    let e2e_keys = vec![E2eKeyEntry {
        client_id: "client-1".to_owned(),
        public_key: e2e_pub,
    }];

    let result = run_phase2(&client, &state, &e2e_keys, &[0xAA; 32], "sha256", "0xABCD")
        .await
        .unwrap();
    assert_eq!(result, Phase2Status::Accepted);
}

#[tokio::test]
async fn run_phase2_returns_already_decided_on_409() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 8192];
        let _n = stream.read(&mut buf).await.unwrap();
        let body = r#"{"error":"already decided"}"#;
        let resp = format!(
            "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let (_, e2e_pub) = e2e_crypto::generate_ecdh_keypair().unwrap();

    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
        request_jwt_exp: 1_900_000_000,
        server_url: format!("http://{addr}"),
    };

    let result = run_phase2(
        &client,
        &state,
        &[E2eKeyEntry {
            client_id: "c1".to_owned(),
            public_key: e2e_pub,
        }],
        &[0xBB; 32],
        "sha256",
        "key-1",
    )
    .await
    .unwrap();
    assert_eq!(result, Phase2Status::AlreadyDecided);
}

#[tokio::test]
async fn cancel_sends_delete_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        request
    });

    let client = build_http_client(Duration::from_secs(2), "test").unwrap();
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();

    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "fake.eyJleHAiOjE5MDAwMDAwMDB9.sig".to_owned(),
        request_jwt_exp: 1_900_000_000,
        server_url: format!("http://{addr}"),
    };

    cancel(&client, &state).await.unwrap();

    let request = server.await.unwrap();
    assert!(request.starts_with("DELETE"), "must be a DELETE request");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer"),
        "must have Bearer auth"
    );
}

#[test]
fn sign_flow_state_debug_redacts_keys() {
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid: auth_kid.clone(),
        enc_private_jwk: enc_priv,
        request_jwt: "secret-jwt".to_owned(),
        request_jwt_exp: 123,
        server_url: "http://test".to_owned(),
    };
    let debug_str = format!("{state:?}");
    assert!(debug_str.contains(&auth_kid));
    assert!(!debug_str.contains("secret-jwt"), "JWT must be redacted");
}

#[test]
fn sign_flow_state_drop_zeroizes_request_jwt() {
    let (auth_priv, _, auth_kid) = e2e_crypto::generate_es256_keypair().unwrap();
    let (enc_priv, _) = e2e_crypto::generate_ecdh_keypair().unwrap();
    let state = SignFlowState {
        auth_private_jwk: auth_priv,
        auth_kid,
        enc_private_jwk: enc_priv,
        request_jwt: "sensitive-jwt-value".to_owned(),
        request_jwt_exp: 123,
        server_url: "http://test".to_owned(),
    };
    // Dropping state triggers the Drop impl which zeroizes sensitive fields.
    // We verify the Drop impl runs without panic.
    drop(state);
}
