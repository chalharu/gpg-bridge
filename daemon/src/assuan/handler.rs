use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use super::command::Command;
use super::response::Response;
use crate::gpg_key_cache::GpgKeyCache;
use crate::sign_flow;

/// Error code for unknown IPC command (e.g., unknown GETINFO subcommand).
///
/// Raw libgpg-error code `GPG_ERR_ASS_UNKNOWN_CMD` with source = 0. We omit
/// the source bits intentionally: gpg clients only inspect the lower 16 bits,
/// and using source 0 avoids pretending to be the real gpg-agent.
const GPG_ERR_ASS_UNKNOWN_CMD: u32 = 275;

/// Error code for unsupported commands (PKDECRYPT, AUTH, etc.).
///
/// Raw libgpg-error code `GPG_ERR_NOT_SUPPORTED` (69) with source = 0.
/// Kept consistent with [`GPG_ERR_ASS_UNKNOWN_CMD`] — see its doc comment.
const GPG_ERR_NOT_SUPPORTED: u32 = 69;

/// Error code for syntax errors (e.g., OPTION with no name).
///
/// Raw libgpg-error code `GPG_ERR_SYNTAX` (147) with source = 0.
const GPG_ERR_SYNTAX: u32 = 147;

/// No secret key (used by HAVEKEY / KEYINFO / READKEY when key not found).
pub(super) const GPG_ERR_NO_SECKEY: u32 = 17;

/// No data available.
const GPG_ERR_NO_DATA: u32 = 58;

/// Timeout (used when SSE wait expires).
pub(super) const GPG_ERR_TIMEOUT: u32 = 62;

/// Invalid length (e.g., SETHASH with wrong hash byte count).
const GPG_ERR_INV_LENGTH: u32 = 71;

/// Operation cancelled.
pub(super) const GPG_ERR_CANCELED: u32 = 99;

/// Missing value (e.g., SETHASH not called before PKSIGN).
pub(super) const GPG_ERR_MISSING_VALUE: u32 = 178;

/// General error for unclassified failures.
pub(super) const GPG_ERR_GENERAL: u32 = 1;

/// Immutable session configuration shared across all commands in a connection.
#[derive(Debug, Clone)]
pub(crate) struct SessionContext {
    socket_path: String,
    pub(super) gpg_key_cache: Arc<GpgKeyCache>,
    pub(super) token_store_path: PathBuf,
    pub(super) http_client: reqwest::Client,
    pub(super) server_url: String,
}

impl SessionContext {
    pub(crate) fn new(
        socket_path: &str,
        gpg_key_cache: Arc<GpgKeyCache>,
        token_store_path: PathBuf,
        http_client: reqwest::Client,
        server_url: String,
    ) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
            gpg_key_cache,
            token_store_path,
            http_client,
            server_url,
        }
    }
}

/// Mutable per-session state that can be modified by commands.
#[derive(Debug, Default)]
pub(super) struct SessionState {
    options: HashMap<String, Option<String>>,
    pub(super) signing_keygrip: Option<String>,
    key_description: Option<String>,
    pub(super) hash_algorithm: Option<u32>,
    pub(super) hash_value: Option<Vec<u8>>,
    pub(super) sign_flow: Option<sign_flow::SignFlowState>,
}

impl SessionState {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn set_option(&mut self, name: String, value: Option<String>) {
        self.options.insert(name, value);
    }

    fn reset(&mut self) {
        self.options.clear();
        self.signing_keygrip = None;
        self.key_description = None;
        self.hash_algorithm = None;
        self.hash_value = None;
        self.sign_flow = None;
    }
}

/// Dispatch a parsed command to its handler and return the appropriate response.
pub(super) async fn handle(
    command: &Command,
    context: &SessionContext,
    state: &mut SessionState,
) -> Response {
    match command {
        Command::Nop | Command::End => Response::Ok(None),
        Command::Option { name, value } => {
            if name.is_empty() {
                return Response::Err {
                    code: GPG_ERR_SYNTAX,
                    message: "option name missing".to_owned(),
                };
            }
            state.set_option(name.clone(), value.clone());
            Response::Ok(None)
        }
        Command::Reset => {
            state.reset();
            Response::Ok(None)
        }
        Command::GetInfo { subcommand } => handle_getinfo(subcommand, context),
        Command::Bye => Response::Ok(None),
        Command::PkDecrypt | Command::Auth => Response::Err {
            code: GPG_ERR_NOT_SUPPORTED,
            message: "Not supported".to_owned(),
        },
        Command::Havekey { keygrips } => handle_havekey(keygrips, context).await,
        // NOTE: --data and --ssh-list flags are parsed but not yet acted upon;
        // the current requirements do not specify behaviour for them.
        Command::Keyinfo {
            keygrip,
            list,
            data: _,
            ssh_list: _,
        } => handle_keyinfo(keygrip.as_deref(), *list, context).await,
        Command::Readkey { keygrip, no_data } => handle_readkey(keygrip, *no_data, context).await,
        Command::Sigkey { keygrip } => {
            state.signing_keygrip = Some(keygrip.clone());
            Response::Ok(None)
        }
        Command::SetKeyDesc { description } => {
            state.key_description = Some(description.clone());
            Response::Ok(None)
        }
        Command::SetHash {
            algorithm,
            hash_hex,
        } => handle_sethash(*algorithm, hash_hex, state),
        Command::Pksign => super::sign_handler::handle_pksign(context, state).await,
        Command::Cancel => super::sign_handler::handle_cancel(context, state).await,
        Command::Unknown { .. } => Response::Err {
            code: GPG_ERR_ASS_UNKNOWN_CMD,
            message: "unknown IPC command".to_owned(),
        },
    }
}

fn handle_getinfo(subcommand: &str, context: &SessionContext) -> Response {
    match subcommand {
        "version" => Response::DataThenOk(env!("CARGO_PKG_VERSION").to_owned()),
        "pid" => Response::DataThenOk(std::process::id().to_string()),
        "socket_name" => Response::DataThenOk(context.socket_path.clone()),
        _ => Response::Err {
            code: GPG_ERR_ASS_UNKNOWN_CMD,
            message: "unknown IPC command".to_owned(),
        },
    }
}

async fn handle_havekey(keygrips: &[String], context: &SessionContext) -> Response {
    match context
        .gpg_key_cache
        .has_any_keygrip(keygrips, &context.token_store_path)
        .await
    {
        Ok(true) => Response::Ok(None),
        Ok(false) => Response::Err {
            code: GPG_ERR_NO_SECKEY,
            message: "No secret key".to_owned(),
        },
        Err(err) => {
            tracing::warn!(?err, "failed to check keygrip cache");
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No secret key".to_owned(),
            }
        }
    }
}

async fn handle_keyinfo(keygrip: Option<&str>, list: bool, context: &SessionContext) -> Response {
    if list {
        return handle_keyinfo_list(context).await;
    }
    let Some(keygrip) = keygrip else {
        return Response::Err {
            code: GPG_ERR_SYNTAX,
            message: "keygrip required".to_owned(),
        };
    };
    match context
        .gpg_key_cache
        .find_by_keygrip(keygrip, &context.token_store_path)
        .await
    {
        Ok(Some(entry)) => Response::StatusThenOk(vec![format_keyinfo_line(&entry.keygrip)]),
        Ok(None) => Response::Err {
            code: GPG_ERR_NO_SECKEY,
            message: "No secret key".to_owned(),
        },
        Err(err) => {
            tracing::warn!(?err, "failed to look up keygrip");
            Response::Err {
                code: GPG_ERR_NO_DATA,
                message: "No data".to_owned(),
            }
        }
    }
}

async fn handle_keyinfo_list(context: &SessionContext) -> Response {
    match context
        .gpg_key_cache
        .get_entries(&context.token_store_path)
        .await
    {
        Ok(entries) if entries.is_empty() => Response::Ok(None),
        Ok(entries) => {
            let lines = entries
                .iter()
                .map(|e| format_keyinfo_line(&e.keygrip))
                .collect();
            Response::StatusThenOk(lines)
        }
        Err(err) => {
            tracing::warn!(?err, "failed to list cached keys");
            Response::Err {
                code: GPG_ERR_NO_DATA,
                message: "No data".to_owned(),
            }
        }
    }
}

fn format_keyinfo_line(keygrip: &str) -> String {
    format!("KEYINFO {keygrip} D - - 1 P - 0 0 -")
}

async fn handle_readkey(keygrip: &str, no_data: bool, context: &SessionContext) -> Response {
    match context
        .gpg_key_cache
        .find_by_keygrip(keygrip, &context.token_store_path)
        .await
    {
        Ok(Some(entry)) => {
            if no_data {
                // --no-data: confirm key exists without converting to S-expression.
                return Response::Ok(None);
            }
            match crate::sexp::jwk_to_sexp(&entry.public_key) {
                Ok(sexp) => Response::DataBinaryThenOk(sexp),
                Err(err) => {
                    tracing::warn!(?err, "failed to convert key to S-expression");
                    Response::Err {
                        code: GPG_ERR_NO_DATA,
                        message: "failed to convert key".to_owned(),
                    }
                }
            }
        }
        Ok(None) => Response::Err {
            code: GPG_ERR_NO_SECKEY,
            message: "No secret key".to_owned(),
        },
        Err(err) => {
            tracing::warn!(?err, "failed to read key from cache");
            Response::Err {
                code: GPG_ERR_NO_DATA,
                message: "No data".to_owned(),
            }
        }
    }
}

fn handle_sethash(algorithm: u32, hash_hex: &str, state: &mut SessionState) -> Response {
    let Some(bytes) = hex_to_bytes(hash_hex) else {
        return Response::Err {
            code: GPG_ERR_SYNTAX,
            message: "invalid hex string".to_owned(),
        };
    };
    const VALID_LENGTHS: &[usize] = &[16, 20, 24, 28, 32, 48, 64];
    if !VALID_LENGTHS.contains(&bytes.len()) {
        return Response::Err {
            code: GPG_ERR_INV_LENGTH,
            message: "invalid hash length".to_owned(),
        };
    }
    state.hash_algorithm = Some(algorithm);
    state.hash_value = Some(bytes);
    Response::Ok(None)
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn handle_nop_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::Nop, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_option_returns_ok() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: "ttyname".to_owned(),
            value: Some("/dev/pts/1".to_owned()),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_option_without_value_returns_ok() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: "lc-messages".to_owned(),
            value: None,
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_reset_returns_ok() {
        let mut state = SessionState::new();
        state.set_option("key".to_owned(), Some("value".to_owned()));
        let response = handle(&Command::Reset, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_reset_clears_options() {
        let mut state = SessionState::new();
        state.set_option("key".to_owned(), Some("value".to_owned()));
        handle(&Command::Reset, &test_context(), &mut state).await;
        // After reset, setting and resetting again should not panic
        assert!(state.options.is_empty());
    }

    #[tokio::test]
    async fn handle_reset_clears_signing_state() {
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD".to_owned());
        state.key_description = Some("desc".to_owned());
        state.hash_algorithm = Some(8);
        state.hash_value = Some(vec![0u8; 32]);
        handle(&Command::Reset, &test_context(), &mut state).await;
        assert!(state.signing_keygrip.is_none());
        assert!(state.key_description.is_none());
        assert!(state.hash_algorithm.is_none());
        assert!(state.hash_value.is_none());
    }

    #[tokio::test]
    async fn handle_getinfo_version() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "version".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::DataThenOk(env!("CARGO_PKG_VERSION").to_owned())
        );
    }

    #[tokio::test]
    async fn handle_getinfo_pid() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "pid".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::DataThenOk(std::process::id().to_string())
        );
    }

    #[tokio::test]
    async fn handle_getinfo_socket_name() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "socket_name".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::DataThenOk("/tmp/test.sock".to_owned()));
    }

    #[tokio::test]
    async fn handle_getinfo_unknown_subcommand() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "foobar".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_getinfo_empty_subcommand() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: String::new(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_end_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::End, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_bye_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::Bye, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
    }

    #[tokio::test]
    async fn handle_pkdecrypt_returns_not_supported() {
        let mut state = SessionState::new();
        let response = handle(&Command::PkDecrypt, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 69,
                message: "Not supported".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_auth_returns_not_supported() {
        let mut state = SessionState::new();
        let response = handle(&Command::Auth, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 69,
                message: "Not supported".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_unknown_returns_unknown_command_error() {
        let mut state = SessionState::new();
        let cmd = Command::Unknown {
            name: "FOOBAR".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_option_empty_name_returns_syntax_error() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: String::new(),
            value: None,
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 147,
                message: "option name missing".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_option_overwrites_previous_value() {
        let mut state = SessionState::new();
        let cmd1 = Command::Option {
            name: "key".to_owned(),
            value: Some("old".to_owned()),
        };
        let cmd2 = Command::Option {
            name: "key".to_owned(),
            value: Some("new".to_owned()),
        };
        handle(&cmd1, &test_context(), &mut state).await;
        handle(&cmd2, &test_context(), &mut state).await;
        assert_eq!(state.options.get("key"), Some(&Some("new".to_owned())));
    }

    #[tokio::test]
    async fn handle_sigkey_stores_keygrip() {
        let mut state = SessionState::new();
        let cmd = Command::Sigkey {
            keygrip: "ABCD1234".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
        assert_eq!(state.signing_keygrip, Some("ABCD1234".to_owned()));
    }

    #[tokio::test]
    async fn handle_setkeydesc_stores_description() {
        let mut state = SessionState::new();
        let cmd = Command::SetKeyDesc {
            description: "test desc".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
        assert_eq!(state.key_description, Some("test desc".to_owned()));
    }

    #[tokio::test]
    async fn handle_sethash_valid_sha256() {
        let mut state = SessionState::new();
        let hash = "aa".repeat(32); // 32 bytes
        let cmd = Command::SetHash {
            algorithm: 8,
            hash_hex: hash,
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(response, Response::Ok(None));
        assert_eq!(state.hash_algorithm, Some(8));
        assert_eq!(state.hash_value.as_ref().map(|v| v.len()), Some(32));
    }

    #[tokio::test]
    async fn handle_sethash_invalid_length() {
        let mut state = SessionState::new();
        let hash = "aa".repeat(5); // 5 bytes, not a valid hash length
        let cmd = Command::SetHash {
            algorithm: 8,
            hash_hex: hash,
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 71,
                message: "invalid hash length".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_sethash_invalid_hex() {
        let mut state = SessionState::new();
        let cmd = Command::SetHash {
            algorithm: 8,
            hash_hex: "GGGG".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 147,
                message: "invalid hex string".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_sethash_odd_hex_length() {
        let mut state = SessionState::new();
        let cmd = Command::SetHash {
            algorithm: 8,
            hash_hex: "ABC".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: 147,
                message: "invalid hex string".to_owned(),
            }
        );
    }

    #[test]
    fn hex_to_bytes_valid() {
        assert_eq!(hex_to_bytes("aaBB01"), Some(vec![0xaa, 0xbb, 0x01]));
    }

    #[test]
    fn hex_to_bytes_empty() {
        assert_eq!(hex_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn hex_to_bytes_odd_length() {
        assert_eq!(hex_to_bytes("abc"), None);
    }

    #[test]
    fn hex_to_bytes_invalid_chars() {
        assert_eq!(hex_to_bytes("GGGG"), None);
    }

    #[tokio::test]
    async fn handle_pksign_without_keygrip_returns_no_seckey() {
        let mut state = SessionState::new();
        state.hash_algorithm = Some(8);
        state.hash_value = Some(vec![0u8; 32]);
        let response = handle(&Command::Pksign, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No secret key".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_without_hash_returns_missing_value() {
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD1234".to_owned());
        let response = handle(&Command::Pksign, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_MISSING_VALUE,
                message: "Missing hash value".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_without_hash_value_returns_missing_value() {
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD1234".to_owned());
        state.hash_algorithm = Some(8);
        // hash_value is None
        let response = handle(&Command::Pksign, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_MISSING_VALUE,
                message: "Missing hash value".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_cancel_returns_canceled() {
        let mut state = SessionState::new();
        let response = handle(&Command::Cancel, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_CANCELED,
                message: "Operation cancelled".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_reset_clears_sign_flow() {
        let mut state = SessionState::new();
        // Simulate having a sign flow (we can't easily construct one here,
        // but reset should handle None gracefully)
        assert!(state.sign_flow.is_none());
        handle(&Command::Reset, &test_context(), &mut state).await;
        assert!(state.sign_flow.is_none());
    }

    #[tokio::test]
    async fn handle_pksign_unsupported_algo_returns_general_error() {
        let mut state = SessionState::new();
        state.signing_keygrip = Some("ABCD1234".to_owned());
        state.hash_algorithm = Some(255); // unknown algorithm
        state.hash_value = Some(vec![0u8; 32]);
        let response = handle(&Command::Pksign, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_GENERAL,
                message: "Unsupported hash algorithm".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn handle_pksign_with_valid_params_but_unknown_key_returns_no_seckey() {
        let mut state = SessionState::new();
        state.signing_keygrip = Some("DEADBEEF".to_owned());
        state.hash_algorithm = Some(8); // sha256
        state.hash_value = Some(vec![0u8; 32]);
        // test_context points to localhost:0 so find_by_keygrip will fail
        let response = handle(&Command::Pksign, &test_context(), &mut state).await;
        assert_eq!(
            response,
            Response::Err {
                code: GPG_ERR_NO_SECKEY,
                message: "No secret key".to_owned(),
            }
        );
    }
}
