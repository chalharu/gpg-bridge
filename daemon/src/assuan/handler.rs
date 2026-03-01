use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroize;

use super::command::Command;
use super::error_code::{
    GPG_ERR_ASS_UNKNOWN_CMD, GPG_ERR_INV_LENGTH, GPG_ERR_NO_DATA, GPG_ERR_NO_SECKEY,
    GPG_ERR_NOT_SUPPORTED, GPG_ERR_SYNTAX,
};
use super::response::Response;
use crate::gpg_key_cache::GpgKeyCache;
use crate::sign_flow;

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
        if let Some(ref mut hash) = self.hash_value {
            hash.zeroize();
        }
        self.hash_value = None;
        self.sign_flow = None;
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        if let Some(ref mut hash) = self.hash_value {
            hash.zeroize();
        }
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
        Command::PkDecrypt
        | Command::Auth
        | Command::GenKey
        | Command::ImportKey
        | Command::ExportKey
        | Command::DeleteKey
        | Command::GetPassphrase
        | Command::Scd
        | Command::Learn => Response::Err {
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
#[path = "handler_tests.rs"]
mod tests;
