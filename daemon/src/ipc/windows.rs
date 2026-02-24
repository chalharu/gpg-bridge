pub(super) fn normalize_pipe_name(endpoint: &str) -> String {
    if endpoint.starts_with(r"\\.\pipe\") {
        return endpoint.to_owned();
    }

    let normalized = endpoint
        .chars()
        .map(|value| match value {
            '\\' | '/' | ':' => '_',
            _ => value,
        })
        .collect::<String>();

    format!(r"\\.\pipe\{normalized}")
}

#[cfg(windows)]
fn create_named_pipe_server(
    pipe_name: &str,
    first_instance: bool,
) -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut options = ServerOptions::new();
    if first_instance {
        options.first_pipe_instance(true);
    }

    options
        .create(pipe_name)
        .map_err(|error| anyhow::anyhow!("failed to create named pipe {pipe_name}: {error}"))
}

#[cfg(windows)]
pub(super) async fn run_windows_accept_loop(
    pipe_name: &str,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    socket_path: String,
) -> anyhow::Result<()> {
    use tracing::{info, warn};

    use super::ACCEPT_ERROR_BACKOFF;

    let mut listener = create_named_pipe_server(pipe_name, true)?;
    info!(pipe_name = %pipe_name, "ipc named pipe listener started");

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    info!("ipc named pipe listener stopping");
                    return Ok(());
                }
            }
            connected = listener.connect() => {
                if let Err(error) = connected {
                    warn!(?error, "failed to accept named pipe connection");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    match create_named_pipe_server(pipe_name, false) {
                        Ok(new_listener) => listener = new_listener,
                        Err(error) => {
                            return Err(anyhow::anyhow!("failed to recreate named pipe after accept error: {error}"));
                        }
                    }
                    continue;
                }
                info!(pipe_name = %pipe_name, "ipc named pipe connection accepted");

                let stream = listener;
                let connection_socket_path = socket_path.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_windows_connection(stream, connection_socket_path).await {
                        warn!(?error, "ipc named pipe connection handler failed");
                    }
                });

                listener = create_named_pipe_server(pipe_name, false)?;
            }
        }
    }
}

#[cfg(windows)]
async fn handle_windows_connection(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    socket_path: String,
) -> anyhow::Result<()> {
    let context = crate::assuan::SessionContext::new(&socket_path);
    crate::assuan::run_session(stream, &context).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pipe_name_preserves_full_pipe_prefix() {
        let result = normalize_pipe_name(r"\\.\pipe\mypipe");
        assert_eq!(result, r"\\.\pipe\mypipe");
    }

    #[test]
    fn normalize_pipe_name_adds_prefix_and_normalizes_slashes() {
        let result = normalize_pipe_name("path/to/pipe");
        assert_eq!(result, r"\\.\pipe\path_to_pipe");
    }

    #[test]
    fn normalize_pipe_name_normalizes_backslashes_and_colons() {
        let result = normalize_pipe_name(r"C:\gpg\agent");
        assert_eq!(result, r"\\.\pipe\C__gpg_agent");
    }

    #[test]
    fn normalize_pipe_name_handles_plain_name() {
        let result = normalize_pipe_name("gpg-agent");
        assert_eq!(result, r"\\.\pipe\gpg-agent");
    }
}
