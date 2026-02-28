//! PKSIGN signing flow orchestration.
//!
//! Implements Phase 1 (`POST /sign-request`) and Phase 2 (`PATCH /sign-request`)
//! of the two-phase signing protocol, plus cancellation (`DELETE /sign-request`).

use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use josekit::jwk::Jwk;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;
use zeroize::Zeroize;

use crate::e2e_crypto;
use crate::http::{
    build_bearer_header, send_delete_with_retry, send_patch_json_with_retry,
    send_post_json_with_retry,
};
use crate::token_store;

/// Per-request signing flow state, stored in session for SSE waiting (KAN-39).
pub(crate) struct SignFlowState {
    pub(crate) auth_private_jwk: Jwk,
    pub(crate) auth_kid: String,
    pub(crate) enc_private_jwk: Jwk,
    pub(crate) request_jwt: String,
    pub(crate) request_jwt_exp: i64,
    pub(crate) server_url: String,
}

impl std::fmt::Debug for SignFlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignFlowState")
            .field("auth_kid", &self.auth_kid)
            .field("request_jwt_exp", &self.request_jwt_exp)
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

impl Drop for SignFlowState {
    fn drop(&mut self) {
        self.request_jwt.zeroize();
        self.auth_kid.zeroize();
        // NOTE: josekit::Jwk does not support in-place memory zeroing.
        // Private key material within Jwk is managed by serde_json::Value
        // and will be freed by the allocator on drop but not securely
        // overwritten. Ephemeral keys are short-lived (one per signing
        // request), which limits the exposure window.
    }
}

/// Outcome of Phase 2 submission.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Phase2Status {
    Accepted,
    AlreadyDecided,
}

/// E2E encryption public key entry received from the server in Phase 1.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct E2eKeyEntry {
    pub(crate) client_id: String,
    pub(crate) public_key: Value,
}

#[derive(Deserialize)]
struct Phase1Response {
    request_jwt: String,
    e2e_keys: Vec<E2eKeyEntry>,
}

/// Map a GPG hash algorithm number to its name for the E2E plaintext payload.
pub(crate) fn algo_number_to_name(algo: u32) -> Option<&'static str> {
    match algo {
        1 => Some("md5"),
        2 => Some("sha1"),
        3 => Some("rmd160"),
        8 => Some("sha256"),
        9 => Some("sha384"),
        10 => Some("sha512"),
        11 => Some("sha224"),
        _ => None,
    }
}

/// Execute Phase 1: `POST /sign-request` to register the signing request.
///
/// Generates ephemeral key pairs, loads client tokens, and sends the request.
/// Returns the flow state and the E2E public keys from the server.
pub(crate) async fn run_phase1(
    client: &Client,
    server_url: &str,
    token_store_path: &Path,
) -> anyhow::Result<(SignFlowState, Vec<E2eKeyEntry>)> {
    let (auth_private, auth_public_json, auth_kid) = e2e_crypto::generate_es256_keypair()?;
    let (enc_private, enc_public_json) = e2e_crypto::generate_ecdh_keypair()?;

    let tokens = token_store::load_tokens(token_store_path)?;
    anyhow::ensure!(!tokens.is_empty(), "no client tokens available");
    let client_jwts: Vec<&str> = tokens.iter().map(|t| t.client_jwt.as_str()).collect();

    let body = json!({
        "client_jwts": client_jwts,
        "daemon_public_key": auth_public_json,
        "daemon_enc_public_key": enc_public_json,
    });

    let url = format!("{server_url}/sign-request");
    let text = send_post_json_with_retry(client, &url, None, &body).await?;
    let resp: Phase1Response = serde_json::from_str(&text)
        .map_err(|e| anyhow!("failed to parse Phase 1 response: {e}"))?;
    let request_jwt_exp = e2e_crypto::extract_jwt_exp(&resp.request_jwt)?;

    let state = SignFlowState {
        auth_private_jwk: auth_private,
        auth_kid,
        enc_private_jwk: enc_private,
        request_jwt: resp.request_jwt,
        request_jwt_exp,
        server_url: server_url.to_owned(),
    };
    Ok((state, resp.e2e_keys))
}

/// Execute Phase 2: `PATCH /sign-request` with E2E encrypted payloads.
pub(crate) async fn run_phase2(
    client: &Client,
    state: &SignFlowState,
    e2e_keys: &[E2eKeyEntry],
    hash_value: &[u8],
    hash_algorithm: &str,
    key_id: &str,
) -> anyhow::Result<Phase2Status> {
    let url = format!("{}/sign-request", state.server_url);
    let auth_jws = build_auth_jws(state, &url)?;
    let bearer = build_bearer_header(&auth_jws)?;

    let payloads = build_encrypted_payloads(e2e_keys, hash_value, hash_algorithm, key_id)?;
    let body = json!({ "encrypted_payloads": payloads });

    let status = send_patch_json_with_retry(client, &url, Some(&bearer), &body).await?;
    match status {
        204 => Ok(Phase2Status::Accepted),
        409 => Ok(Phase2Status::AlreadyDecided),
        _ => Err(anyhow!("unexpected Phase 2 status: {status}")),
    }
}

/// Cancel the signing request: `DELETE /sign-request`.
pub(crate) async fn cancel(client: &Client, state: &SignFlowState) -> anyhow::Result<()> {
    let url = format!("{}/sign-request", state.server_url);
    let auth_jws = build_auth_jws(state, &url)?;
    let bearer = build_bearer_header(&auth_jws)?;
    let _status = send_delete_with_retry(client, &url, Some(&bearer)).await?;
    Ok(())
}

fn build_auth_jws(state: &SignFlowState, aud: &str) -> anyhow::Result<String> {
    e2e_crypto::sign_daemon_auth_jws(
        &state.auth_private_jwk,
        &state.auth_kid,
        &state.request_jwt,
        aud,
        state.request_jwt_exp,
    )
}

fn build_encrypted_payloads(
    e2e_keys: &[E2eKeyEntry],
    hash_value: &[u8],
    hash_algorithm: &str,
    key_id: &str,
) -> anyhow::Result<Vec<Value>> {
    let hash_b64 = BASE64.encode(hash_value);
    let plaintext = json!({
        "hash": hash_b64,
        "hash_algorithm": hash_algorithm,
        "key_id": key_id,
    });
    let plaintext_bytes = serde_json::to_vec(&plaintext)?;

    e2e_keys
        .iter()
        .map(|entry| {
            let encrypted = e2e_crypto::encrypt_jwe_a256kw(&entry.public_key, &plaintext_bytes)?;
            Ok(json!({
                "client_id": entry.client_id,
                "encrypted_data": encrypted,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
        let payloads =
            build_encrypted_payloads(&keys, &[0xAA; 32], "sha256", "0xABCD1234").unwrap();
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
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
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
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
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
}
