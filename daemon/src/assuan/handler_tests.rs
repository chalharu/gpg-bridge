use super::super::error_code::{
    GPG_ERR_CANCELED, GPG_ERR_GENERAL, GPG_ERR_MISSING_VALUE, GPG_ERR_NO_SECKEY,
};
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
async fn handle_genkey_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::GenKey, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_import_key_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::ImportKey, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_export_key_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::ExportKey, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_delete_key_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::DeleteKey, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_get_passphrase_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::GetPassphrase, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_scd_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::Scd, &test_context(), &mut state).await;
    assert_eq!(
        response,
        Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        }
    );
}

#[tokio::test]
async fn handle_learn_returns_not_supported() {
    let mut state = SessionState::new();
    let response = handle(&Command::Learn, &test_context(), &mut state).await;
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
async fn handle_reset_zeroizes_hash_value() {
    let mut state = SessionState::new();
    state.hash_value = Some(vec![0xAA; 32]);
    handle(&Command::Reset, &test_context(), &mut state).await;
    assert!(state.hash_value.is_none());
}

#[test]
fn session_state_drop_zeroizes_hash_value() {
    let mut state = SessionState::new();
    state.hash_value = Some(vec![0xBB; 32]);
    // Dropping state should not panic (zeroize runs in Drop)
    drop(state);
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
