use std::collections::HashMap;

use super::command::Command;
use super::response::Response;

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

/// Immutable session configuration shared across all commands in a connection.
#[derive(Debug, Clone)]
pub(crate) struct SessionContext {
    socket_path: String,
}

impl SessionContext {
    pub(crate) fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
        }
    }
}

/// Mutable per-session state that can be modified by commands.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    options: HashMap<String, Option<String>>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn set_option(&mut self, name: String, value: Option<String>) {
        self.options.insert(name, value);
    }

    fn reset(&mut self) {
        self.options.clear();
    }
}

/// Dispatch a parsed command to its handler and return the appropriate response.
pub(crate) fn handle(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> SessionContext {
        SessionContext::new("/tmp/test.sock")
    }

    #[test]
    fn handle_nop_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::Nop, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_option_returns_ok() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: "ttyname".to_owned(),
            value: Some("/dev/pts/1".to_owned()),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_option_without_value_returns_ok() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: "lc-messages".to_owned(),
            value: None,
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_reset_returns_ok() {
        let mut state = SessionState::new();
        state.set_option("key".to_owned(), Some("value".to_owned()));
        let response = handle(&Command::Reset, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_reset_clears_options() {
        let mut state = SessionState::new();
        state.set_option("key".to_owned(), Some("value".to_owned()));
        handle(&Command::Reset, &test_context(), &mut state);
        // After reset, setting and resetting again should not panic
        assert!(state.options.is_empty());
    }

    #[test]
    fn handle_getinfo_version() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "version".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::DataThenOk(env!("CARGO_PKG_VERSION").to_owned())
        );
    }

    #[test]
    fn handle_getinfo_pid() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "pid".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::DataThenOk(std::process::id().to_string())
        );
    }

    #[test]
    fn handle_getinfo_socket_name() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "socket_name".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(response, Response::DataThenOk("/tmp/test.sock".to_owned()));
    }

    #[test]
    fn handle_getinfo_unknown_subcommand() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: "foobar".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[test]
    fn handle_getinfo_empty_subcommand() {
        let mut state = SessionState::new();
        let cmd = Command::GetInfo {
            subcommand: String::new(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[test]
    fn handle_end_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::End, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_bye_returns_ok() {
        let mut state = SessionState::new();
        let response = handle(&Command::Bye, &test_context(), &mut state);
        assert_eq!(response, Response::Ok(None));
    }

    #[test]
    fn handle_pkdecrypt_returns_not_supported() {
        let mut state = SessionState::new();
        let response = handle(&Command::PkDecrypt, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 69,
                message: "Not supported".to_owned(),
            }
        );
    }

    #[test]
    fn handle_auth_returns_not_supported() {
        let mut state = SessionState::new();
        let response = handle(&Command::Auth, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 69,
                message: "Not supported".to_owned(),
            }
        );
    }

    #[test]
    fn handle_unknown_returns_unknown_command_error() {
        let mut state = SessionState::new();
        let cmd = Command::Unknown {
            name: "FOOBAR".to_owned(),
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 275,
                message: "unknown IPC command".to_owned(),
            }
        );
    }

    #[test]
    fn handle_option_empty_name_returns_syntax_error() {
        let mut state = SessionState::new();
        let cmd = Command::Option {
            name: String::new(),
            value: None,
        };
        let response = handle(&cmd, &test_context(), &mut state);
        assert_eq!(
            response,
            Response::Err {
                code: 147,
                message: "option name missing".to_owned(),
            }
        );
    }

    #[test]
    fn handle_option_overwrites_previous_value() {
        let mut state = SessionState::new();
        let cmd1 = Command::Option {
            name: "key".to_owned(),
            value: Some("old".to_owned()),
        };
        let cmd2 = Command::Option {
            name: "key".to_owned(),
            value: Some("new".to_owned()),
        };
        handle(&cmd1, &test_context(), &mut state);
        handle(&cmd2, &test_context(), &mut state);
        assert_eq!(state.options.get("key"), Some(&Some("new".to_owned())));
    }
}
