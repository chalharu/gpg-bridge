use super::*;
use tokio::io::AsyncReadExt;

/// Send the given raw input to a session and return all output produced.
async fn run_test_session(socket_path: &str, client_input: &str) -> String {
    let (server, mut client) = tokio::io::duplex(4096);
    let socket_path = socket_path.to_owned();

    let session = tokio::spawn(async move {
        let cache = crate::gpg_key_cache::GpgKeyCache::new(
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
            None,
        );
        let context = SessionContext::new(
            &socket_path,
            cache,
            std::path::PathBuf::from("/tmp/test-tokens"),
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
        );
        run_session(server, &context).await
    });

    client.write_all(client_input.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let mut output = Vec::new();
    client.read_to_end(&mut output).await.unwrap();

    let _ = session.await;

    String::from_utf8(output).unwrap()
}

#[tokio::test]
async fn session_sends_greeting_and_handles_bye() {
    let output = run_test_session("/tmp/test.sock", "BYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\n");
}

#[tokio::test]
async fn session_nop_returns_ok() {
    let output = run_test_session("/tmp/test.sock", "NOP\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_option_returns_ok() {
    let output = run_test_session("/tmp/test.sock", "OPTION ttyname=/dev/pts/1\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_reset_returns_ok() {
    let output = run_test_session("/tmp/test.sock", "RESET\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_end_returns_ok() {
    let output = run_test_session("/tmp/test.sock", "END\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_getinfo_version() {
    let output = run_test_session("/tmp/test.sock", "GETINFO version\nBYE\n").await;
    let expected = format!(
        "OK Pleased to meet you\nD {}\nOK\nOK\n",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(output, expected);
}

#[tokio::test]
async fn session_getinfo_pid() {
    let output = run_test_session("/tmp/test.sock", "GETINFO pid\nBYE\n").await;
    let expected = format!("OK Pleased to meet you\nD {}\nOK\nOK\n", std::process::id());
    assert_eq!(output, expected);
}

#[tokio::test]
async fn session_getinfo_socket_name() {
    let output = run_test_session("/tmp/custom.sock", "GETINFO socket_name\nBYE\n").await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nD /tmp/custom.sock\nOK\nOK\n"
    );
}

#[tokio::test]
async fn session_getinfo_unknown_subcommand() {
    let output = run_test_session("/tmp/test.sock", "GETINFO foobar\nBYE\n").await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 275 unknown IPC command\nOK\n"
    );
}

#[tokio::test]
async fn session_pkdecrypt_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "PKDECRYPT\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_auth_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "AUTH\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_genkey_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "GENKEY\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_import_key_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "IMPORT_KEY\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_import_keyfiles_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "IMPORT_KEYFILES\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_export_key_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "EXPORT_KEY\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_delete_key_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "DELETE_KEY\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_get_passphrase_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "GET_PASSPHRASE\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_scd_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "SCD\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_learn_returns_not_supported() {
    let output = run_test_session("/tmp/test.sock", "LEARN\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nERR 69 Not supported\nOK\n");
}

#[tokio::test]
async fn session_unknown_command_returns_unknown_error() {
    let output = run_test_session("/tmp/test.sock", "FOOBAR\nBYE\n").await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 275 unknown IPC command\nOK\n"
    );
}

#[tokio::test]
async fn session_eof_closes_gracefully() {
    let output = run_test_session("/tmp/test.sock", "NOP\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\n");
}

#[tokio::test]
async fn session_empty_lines_are_skipped() {
    let output = run_test_session("/tmp/test.sock", "\n\nNOP\n\nBYE\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_line_too_long() {
    let long_line = "A".repeat(1000);
    let input = format!("{long_line}\nBYE\n");
    let output = run_test_session("/tmp/test.sock", &input).await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 276 Line too long\nOK\n"
    );
}

#[tokio::test]
async fn session_very_long_line_drains_then_continues() {
    // A line much larger than MAX_LINE_LENGTH that spans multiple internal
    // BufReader buffers. This exercises the multi-iteration drain loop.
    let long_line = "B".repeat(10_000);
    let input = format!("{long_line}\nNOP\nBYE\n");
    let output = run_test_session("/tmp/test.sock", &input).await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 276 Line too long\nOK\nOK\n"
    );
}

#[tokio::test]
async fn session_very_long_line_without_newline_drains_to_eof() {
    // A long line without a trailing newline at all (EOF after overflow).
    let long_line = "C".repeat(5_000);
    let output = run_test_session("/tmp/test.sock", &long_line).await;
    assert_eq!(output, "OK Pleased to meet you\nERR 276 Line too long\n");
}

#[tokio::test]
async fn session_line_at_max_length_is_accepted() {
    // 999 chars + \n = 1000 bytes, exactly at the limit → accepted as unknown command
    let line = "A".repeat(999);
    let input = format!("{line}\nBYE\n");
    let output = run_test_session("/tmp/test.sock", &input).await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 275 unknown IPC command\nOK\n"
    );
}

#[tokio::test]
async fn session_multiple_commands_sequence() {
    let input = "NOP\nOPTION ttyname=/dev/pts/1\nGETINFO version\nRESET\nBYE\n";
    let output = run_test_session("/tmp/test.sock", input).await;
    let expected = format!(
        "OK Pleased to meet you\nOK\nOK\nD {}\nOK\nOK\nOK\n",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(output, expected);
}

#[tokio::test]
async fn session_case_insensitive_commands() {
    let output = run_test_session("/tmp/test.sock", "nop\nbye\n").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\nOK\n");
}

#[tokio::test]
async fn session_immediate_eof() {
    let output = run_test_session("/tmp/test.sock", "").await;
    assert_eq!(output, "OK Pleased to meet you\n");
}

#[tokio::test]
async fn session_command_without_trailing_newline() {
    let output = run_test_session("/tmp/test.sock", "NOP").await;
    assert_eq!(output, "OK Pleased to meet you\nOK\n");
}

#[tokio::test]
async fn session_option_no_args_returns_syntax_error() {
    let output = run_test_session("/tmp/test.sock", "OPTION\nBYE\n").await;
    assert_eq!(
        output,
        "OK Pleased to meet you\nERR 147 option name missing\nOK\n"
    );
}
