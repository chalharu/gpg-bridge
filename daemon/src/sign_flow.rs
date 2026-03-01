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
#[path = "sign_flow_tests.rs"]
mod tests;
