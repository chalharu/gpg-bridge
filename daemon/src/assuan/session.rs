use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::debug;

use super::command::Command;
use super::handler::{SessionContext, SessionState, handle};
use super::response::Response;

/// Maximum Assuan protocol line length in bytes (including the trailing newline).
const MAX_LINE_LENGTH: usize = 1000;

/// Buffer capacity used for bounded line reads. One byte beyond the maximum
/// allows detecting lines that exceed the protocol limit.
const READ_BUF_CAPACITY: u64 = (MAX_LINE_LENGTH as u64) + 1;

/// Error code for line-too-long condition (GPG_ERR_ASS_LINE_TOO_LONG).
const GPG_ERR_ASS_LINE_TOO_LONG: u32 = 276;

/// Greeting message sent when a client connects.
const GREETING: &str = "Pleased to meet you";

/// Run the Assuan protocol session loop over the given bidirectional stream.
///
/// Sends a greeting, then reads commands line-by-line, dispatches them through
/// the handler, and writes responses until the client sends `BYE` or disconnects.
pub(crate) async fn run_session<S>(stream: S, context: &SessionContext) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let mut state = SessionState::new();
    write_response(&mut stream, &Response::Ok(Some(GREETING.to_owned()))).await?;

    loop {
        match read_bounded_line(&mut stream).await? {
            ReadLineResult::Eof => {
                debug!("client disconnected (EOF)");
                break;
            }
            ReadLineResult::TooLong => write_too_long_error(&mut stream).await?,
            ReadLineResult::Empty => {}
            ReadLineResult::Line(trimmed) => {
                if process_line(&mut stream, &trimmed, context, &mut state).await? {
                    debug!("client sent BYE, closing session");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Process a single parsed command line. Returns `true` if the session should end (BYE).
async fn process_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    trimmed: &str,
    context: &SessionContext,
    state: &mut SessionState,
) -> anyhow::Result<bool> {
    let command = Command::parse(trimmed);
    debug!(?command, "received command");
    let is_bye = matches!(command, Command::Bye);
    let response = handle(&command, context, state);
    write_response(writer, &response).await?;
    Ok(is_bye)
}

/// Send a line-too-long error response.
async fn write_too_long_error<W: AsyncWrite + Unpin>(writer: &mut W) -> anyhow::Result<()> {
    let err = Response::Err {
        code: GPG_ERR_ASS_LINE_TOO_LONG,
        message: "Line too long".to_owned(),
    };
    write_response(writer, &err).await
}

/// Outcome of a single bounded line read.
enum ReadLineResult {
    Eof,
    TooLong,
    Empty,
    /// A valid, trimmed (no trailing newline) non-empty line.
    Line(String),
}

/// Read one line from the stream, enforcing [`MAX_LINE_LENGTH`] **before**
/// buffering completes so that a malicious client cannot exhaust memory.
async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<ReadLineResult> {
    let mut buf = String::new();
    let bytes_read = reader.take(READ_BUF_CAPACITY).read_line(&mut buf).await?;

    if bytes_read == 0 {
        return Ok(ReadLineResult::Eof);
    }

    // If the read filled the capacity and there was no newline, the line is too
    // long. Drain the remainder of the over-long line so the next read starts
    // at a fresh line boundary.
    if !buf.ends_with('\n') && buf.len() as u64 >= READ_BUF_CAPACITY {
        drain_until_newline(reader).await?;
        return Ok(ReadLineResult::TooLong);
    }

    // The newline was found within the capacity, but the total line (including
    // the newline) still exceeds the protocol limit.
    if buf.len() > MAX_LINE_LENGTH {
        return Ok(ReadLineResult::TooLong);
    }

    let trimmed = buf.trim_end();
    if trimmed.is_empty() {
        return Ok(ReadLineResult::Empty);
    }

    Ok(ReadLineResult::Line(trimmed.to_owned()))
}

/// Discard bytes from the reader until a newline is found or EOF is reached.
///
/// Uses `fill_buf` / `consume` to avoid allocating a buffer for discarded data.
async fn drain_until_newline<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> anyhow::Result<()> {
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            break;
        }
        let found = buf.iter().position(|&b| b == b'\n');
        let n = found.map_or(buf.len(), |p| p + 1);
        reader.consume(n);
        if found.is_some() {
            break;
        }
    }
    Ok(())
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Response,
) -> anyhow::Result<()> {
    writer.write_all(response.format().as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Send the given raw input to a session and return all output produced.
    async fn run_test_session(socket_path: &str, client_input: &str) -> String {
        let (server, mut client) = tokio::io::duplex(4096);
        let socket_path = socket_path.to_owned();

        let session = tokio::spawn(async move {
            let context = SessionContext::new(&socket_path);
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
}
