//! Signing-related Assuan command handlers (PKSIGN, CANCEL).

use super::error_code::{
    GPG_ERR_CANCELED, GPG_ERR_GENERAL, GPG_ERR_MISSING_VALUE, GPG_ERR_NO_SECKEY, GPG_ERR_TIMEOUT,
};
use super::handler::{SessionContext, SessionState};
use super::response::Response;
use crate::sign_event_sse::{self, SignEventSseConfig, SignResult};
use crate::sign_flow;

pub(super) async fn handle_pksign(context: &SessionContext, state: &mut SessionState) -> Response {
    let keygrip = match &state.signing_keygrip {
        Some(kg) => kg.clone(),
        None => return err_response(GPG_ERR_NO_SECKEY, "No secret key"),
    };
    let algorithm = match state.hash_algorithm {
        Some(a) => a,
        None => return err_response(GPG_ERR_MISSING_VALUE, "Missing hash value"),
    };
    let hash_value = match &state.hash_value {
        Some(h) => h.clone(),
        None => return err_response(GPG_ERR_MISSING_VALUE, "Missing hash value"),
    };
    let algo_name = match sign_flow::algo_number_to_name(algorithm) {
        Some(n) => n,
        None => return err_response(GPG_ERR_GENERAL, "Unsupported hash algorithm"),
    };
    let key_id = match resolve_key_id(&keygrip, context).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match execute_sign_flow(context, state, &hash_value, algo_name, &key_id).await {
        Ok(()) => wait_for_signature(context, state).await,
        Err(err) => {
            tracing::warn!(?err, "sign flow failed");
            err_response(GPG_ERR_GENERAL, "Sign request failed")
        }
    }
}

async fn wait_for_signature(context: &SessionContext, state: &mut SessionState) -> Response {
    let Some(flow_state) = &state.sign_flow else {
        return err_response(GPG_ERR_GENERAL, "No active sign flow");
    };
    let config = SignEventSseConfig::default();
    let result =
        sign_event_sse::wait_for_sign_result(&context.http_client, &config, flow_state).await;
    state.sign_flow = None;
    map_sign_result(result)
}

fn map_sign_result(result: anyhow::Result<SignResult>) -> Response {
    match result {
        Ok(SignResult::Approved { signature }) => Response::DataBinaryThenOk(signature),
        Ok(SignResult::Denied) => err_response(GPG_ERR_CANCELED, "Signing denied by user"),
        Ok(SignResult::Unavailable) => err_response(GPG_ERR_NO_SECKEY, "No device available"),
        Ok(SignResult::Expired | SignResult::Cancelled) => {
            err_response(GPG_ERR_TIMEOUT, "Request expired")
        }
        Err(err) => err_response(GPG_ERR_TIMEOUT, &format!("SSE error: {err}")),
    }
}

pub(super) async fn handle_cancel(context: &SessionContext, state: &mut SessionState) -> Response {
    if let Some(flow_state) = state.sign_flow.take()
        && let Err(err) = sign_flow::cancel(&context.http_client, &flow_state).await
    {
        tracing::warn!(?err, "sign flow cancel request failed");
    }
    err_response(GPG_ERR_CANCELED, "Operation cancelled")
}

async fn resolve_key_id(keygrip: &str, context: &SessionContext) -> Result<String, Response> {
    match context
        .gpg_key_cache
        .find_by_keygrip(keygrip, &context.token_store_path)
        .await
    {
        Ok(Some(entry)) => Ok(entry.key_id),
        _ => Err(err_response(GPG_ERR_NO_SECKEY, "No secret key")),
    }
}

async fn execute_sign_flow(
    context: &SessionContext,
    state: &mut SessionState,
    hash_value: &[u8],
    algo_name: &str,
    key_id: &str,
) -> anyhow::Result<()> {
    let (flow_state, e2e_keys) = sign_flow::run_phase1(
        &context.http_client,
        &context.server_url,
        &context.token_store_path,
    )
    .await?;
    sign_flow::run_phase2(
        &context.http_client,
        &flow_state,
        &e2e_keys,
        hash_value,
        algo_name,
        key_id,
    )
    .await?;
    state.sign_flow = Some(flow_state);
    Ok(())
}

fn err_response(code: u32, message: &str) -> Response {
    Response::Err {
        code,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::e2e_crypto;
    use crate::gpg_key_cache::GpgKeyCache;
    use crate::sign_flow::SignFlowState;

    fn test_context() -> SessionContext {
        let cache = GpgKeyCache::new(
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
            None,
        );
        SessionContext::new(
            "/tmp/test.sock",
            cache,
            PathBuf::from("/tmp/test-tokens"),
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
        )
    }

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

    #[tokio::test]
    async fn handle_cancel_with_active_flow_returns_canceled() {
        let context = test_context();
        let mut state = SessionState::new();
        state.sign_flow = Some(dummy_flow_state());

        let resp = handle_cancel(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_CANCELED,
                message: "Operation cancelled".to_owned(),
            }
        );
        assert!(
            state.sign_flow.is_none(),
            "flow must be cleared after cancel"
        );
    }

    #[tokio::test]
    async fn handle_cancel_without_flow_returns_canceled() {
        let context = test_context();
        let mut state = SessionState::new();

        let resp = handle_cancel(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_CANCELED,
                message: "Operation cancelled".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn wait_for_signature_without_flow_returns_general_error() {
        let context = test_context();
        let mut state = SessionState::new();
        // sign_flow is None
        let resp = wait_for_signature(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_GENERAL,
                message: "No active sign flow".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_no_keygrip() {
        let context = test_context();
        let mut state = SessionState::new();
        state.hash_algorithm = Some(8);
        state.hash_value = Some(vec![0u8; 32]);

        let resp = handle_pksign(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No secret key".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_no_algorithm() {
        let context = test_context();
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD".to_owned());

        let resp = handle_pksign(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_MISSING_VALUE,
                message: "Missing hash value".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_no_hash_value() {
        let context = test_context();
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD".to_owned());
        state.hash_algorithm = Some(8);

        let resp = handle_pksign(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_MISSING_VALUE,
                message: "Missing hash value".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_unsupported_algo() {
        let context = test_context();
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD".to_owned());
        state.hash_algorithm = Some(255);
        state.hash_value = Some(vec![0u8; 32]);

        let resp = handle_pksign(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_GENERAL,
                message: "Unsupported hash algorithm".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_unknown_key_returns_no_seckey() {
        let context = test_context();
        let mut state = SessionState::new();
        state.signing_keygrip = Some("DEADBEEF".to_owned());
        state.hash_algorithm = Some(8);
        state.hash_value = Some(vec![0u8; 32]);

        let resp = handle_pksign(&context, &mut state).await;
        assert_eq!(
            resp,
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No secret key".to_owned(),
            }
        );
    }

    #[test]
    fn err_response_formats_correctly() {
        let resp = err_response(99, "test message");
        assert_eq!(
            resp,
            Response::Err {
                code: 99,
                message: "test message".to_owned(),
            }
        );
    }

    #[test]
    fn map_sign_result_approved() {
        let result = Ok(SignResult::Approved {
            signature: vec![0xDE, 0xAD],
        });
        assert_eq!(
            map_sign_result(result),
            Response::DataBinaryThenOk(vec![0xDE, 0xAD])
        );
    }

    #[test]
    fn map_sign_result_denied() {
        assert_eq!(
            map_sign_result(Ok(SignResult::Denied)),
            Response::Err {
                code: GPG_ERR_CANCELED,
                message: "Signing denied by user".to_owned(),
            }
        );
    }

    #[test]
    fn map_sign_result_unavailable() {
        assert_eq!(
            map_sign_result(Ok(SignResult::Unavailable)),
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No device available".to_owned(),
            }
        );
    }

    #[test]
    fn map_sign_result_expired() {
        assert_eq!(
            map_sign_result(Ok(SignResult::Expired)),
            Response::Err {
                code: GPG_ERR_TIMEOUT,
                message: "Request expired".to_owned(),
            }
        );
    }

    #[test]
    fn map_sign_result_cancelled() {
        assert_eq!(
            map_sign_result(Ok(SignResult::Cancelled)),
            Response::Err {
                code: GPG_ERR_TIMEOUT,
                message: "Request expired".to_owned(),
            }
        );
    }

    #[test]
    fn map_sign_result_error() {
        let result = Err(anyhow::anyhow!("connection lost"));
        let resp = map_sign_result(result);
        match resp {
            Response::Err { code, message } => {
                assert_eq!(code, GPG_ERR_TIMEOUT);
                assert!(message.contains("connection lost"));
            }
            _ => panic!("expected Err response"),
        }
    }
}
