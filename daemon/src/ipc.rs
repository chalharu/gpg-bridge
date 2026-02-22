use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub struct IpcServer {
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl IpcServer {
    pub async fn start(endpoint: &str) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_server(endpoint, shutdown_rx)?;

        Ok(Self { task, shutdown_tx })
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(true);

        match self.task.await {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!("ipc task join error: {error}")),
        }
    }
}

#[cfg(unix)]
fn spawn_server(
    endpoint: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let socket_path = PathBuf::from(endpoint);
    let listener = bind_unix_listener(&socket_path)?;

    Ok(tokio::spawn(async move {
        let run_result = run_unix_accept_loop(listener, shutdown_rx).await;
        if let Err(error) = cleanup_unix_socket_path(&socket_path) {
            warn!(socket_path = %socket_path.display(), ?error, "failed to cleanup unix socket file");
        }
        run_result
    }))
}

#[cfg(windows)]
fn spawn_server(
    endpoint: &str,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let pipe_name = normalize_pipe_name(endpoint);

    Ok(tokio::spawn(async move {
        run_windows_accept_loop(&pipe_name, shutdown_rx).await
    }))
}

#[cfg(unix)]
fn bind_unix_listener(path: &Path) -> anyhow::Result<tokio::net::UnixListener> {
    prepare_unix_socket_path(path)?;

    let listener = tokio::net::UnixListener::bind(path).map_err(|error| {
        anyhow::anyhow!("failed to bind unix socket {}: {error}", path.display())
    })?;

    set_unix_socket_permissions(path)?;

    info!(socket_path = %path.display(), "ipc unix socket listener started");

    Ok(listener)
}

#[cfg(unix)]
fn prepare_unix_socket_path(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to create parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        anyhow::anyhow!("failed to read socket metadata {}: {error}", path.display())
    })?;

    if !metadata.file_type().is_socket() {
        return Err(anyhow::anyhow!(
            "existing path is not a socket: {}",
            path.display()
        ));
    }

    cleanup_unix_socket_path(path)
}

#[cfg(unix)]
fn cleanup_unix_socket_path(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "failed to remove unix socket {}: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn set_unix_socket_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(|error| {
        anyhow::anyhow!(
            "failed to set unix socket permissions for {}: {error}",
            path.display()
        )
    })
}

#[cfg(unix)]
async fn run_unix_accept_loop(
    listener: tokio::net::UnixListener,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    info!("ipc unix socket listener stopping");
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|error| anyhow::anyhow!("failed to accept unix socket connection: {error}"))?;
                info!("ipc unix socket connection accepted");
                tokio::spawn(async move {
                    if let Err(error) = handle_unix_connection(stream).await {
                        warn!(?error, "ipc unix socket connection handler failed");
                    }
                });
            }
        }
    }
}

#[cfg(unix)]
async fn handle_unix_connection(_stream: tokio::net::UnixStream) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        UNIX_CONNECTION_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    Ok(())
}

#[cfg(windows)]
fn normalize_pipe_name(endpoint: &str) -> String {
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
async fn run_windows_accept_loop(
    pipe_name: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
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
                connected.map_err(|error| anyhow::anyhow!("failed to accept named pipe connection: {error}"))?;
                info!(pipe_name = %pipe_name, "ipc named pipe connection accepted");

                let stream = listener;
                tokio::spawn(async move {
                    if let Err(error) = handle_windows_connection(stream).await {
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
) -> anyhow::Result<()> {
    stream
        .disconnect()
        .map_err(|error| anyhow::anyhow!("failed to disconnect named pipe: {error}"))
}

#[cfg(all(test, unix))]
static UNIX_CONNECTION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    #[cfg(unix)]
    use tokio::net::{UnixListener, UnixStream};

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_listener_replaces_existing_socket_and_sets_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");

        let stale_listener = UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let listener = bind_unix_listener(&socket_path).unwrap();
        let metadata = std::fs::metadata(&socket_path).unwrap();

        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_accepts_connection_and_shutdown_cleans_up_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let before_count = UNIX_CONNECTION_COUNT.load(std::sync::atomic::Ordering::Relaxed);

        let server = IpcServer::start(&socket_path_str).await.unwrap();
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        drop(stream);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let current = UNIX_CONNECTION_COUNT.load(std::sync::atomic::Ordering::Relaxed);
                if current > before_count {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        server.shutdown().await.unwrap();

        assert!(!socket_path.exists());
    }
}
