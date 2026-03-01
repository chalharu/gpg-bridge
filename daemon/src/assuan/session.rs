use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::debug;

use super::command::Command;
use super::error_code::GPG_ERR_ASS_LINE_TOO_LONG;
use super::handler::{SessionContext, SessionState, handle};
use super::response::Response;

/// Maximum Assuan protocol line length in bytes (including the trailing newline).
const MAX_LINE_LENGTH: usize = 1000;

/// Buffer capacity used for bounded line reads. One byte beyond the maximum
/// allows detecting lines that exceed the protocol limit.
const READ_BUF_CAPACITY: u64 = (MAX_LINE_LENGTH as u64) + 1;

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
    let response = handle(&command, context, state).await;
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
    writer.write_all(&response.format()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
