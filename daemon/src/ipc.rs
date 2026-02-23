use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub struct IpcServer {
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
    #[cfg(unix)]
    socket_path: PathBuf,
    #[cfg(unix)]
    compat_socket_path: Option<PathBuf>,
}

impl IpcServer {
    #[cfg(unix)]
    pub async fn start(
        endpoint: &str,
        compat_socket_path: Option<&Path>,
        allow_replace_existing_socket: bool,
    ) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_server(
            endpoint,
            compat_socket_path.map(Path::to_path_buf),
            allow_replace_existing_socket,
            shutdown_rx,
        )?;

        Ok(Self {
            task: Some(task),
            shutdown_tx,
            socket_path: PathBuf::from(endpoint),
            compat_socket_path: compat_socket_path.map(Path::to_path_buf),
        })
    }

    #[cfg(windows)]
    pub async fn start(endpoint: &str) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_server(endpoint, shutdown_rx)?;

        Ok(Self {
            task: Some(task),
            shutdown_tx,
        })
    }

    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        let _ = self.shutdown_tx.send(true);

        let Some(task) = self.task.take() else {
            return Ok(());
        };

        match task.await {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!("ipc task join error: {error}")),
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }

        #[cfg(unix)]
        if let Err(error) = cleanup_unix_socket_path(&self.socket_path) {
            warn!(socket_path = %self.socket_path.display(), ?error, "failed to cleanup unix socket file on drop");
        }

        #[cfg(unix)]
        if let Some(path) = &self.compat_socket_path
            && let Err(error) = cleanup_unix_socket_path(path)
        {
            warn!(socket_path = %path.display(), ?error, "failed to cleanup compatibility unix socket file on drop");
        }
    }
}

#[cfg(unix)]
fn spawn_server(
    endpoint: &str,
    compat_socket_path: Option<PathBuf>,
    allow_replace_existing_socket: bool,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let socket_path = PathBuf::from(endpoint);
    let listener = bind_unix_listener(&socket_path, allow_replace_existing_socket)?;
    if let Some(path) = compat_socket_path.as_deref() {
        create_unix_socket_symlink(path, &socket_path, allow_replace_existing_socket)?;
    }

    Ok(tokio::spawn(async move {
        let run_result = run_unix_accept_loop(listener, shutdown_rx).await;
        if let Err(error) = cleanup_unix_socket_path(&socket_path) {
            warn!(socket_path = %socket_path.display(), ?error, "failed to cleanup unix socket file");
        }
        if let Some(path) = compat_socket_path
            && let Err(error) = cleanup_unix_socket_path(&path)
        {
            warn!(socket_path = %path.display(), ?error, "failed to cleanup compatibility unix socket file");
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
fn bind_unix_listener(
    path: &Path,
    allow_replace_existing_socket: bool,
) -> anyhow::Result<tokio::net::UnixListener> {
    prepare_unix_socket_path(path, allow_replace_existing_socket)?;

    let listener = tokio::net::UnixListener::bind(path).map_err(|error| {
        anyhow::anyhow!("failed to bind unix socket {}: {error}", path.display())
    })?;

    set_unix_socket_permissions(path)?;

    info!(socket_path = %path.display(), "ipc unix socket listener started");

    Ok(listener)
}

#[cfg(unix)]
fn prepare_unix_socket_path(
    path: &Path,
    allow_replace_existing_socket: bool,
) -> anyhow::Result<()> {
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

    if !metadata.file_type().is_socket() && !metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "existing path is not a socket or symlink: {}",
            path.display()
        ));
    }

    if metadata.file_type().is_socket() && !allow_replace_existing_socket {
        return Err(anyhow::anyhow!(
            "existing socket path is a socket and replacement is disabled: {}",
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
fn create_unix_socket_symlink(
    link_path: &Path,
    socket_path: &Path,
    allow_replace_compat_socket: bool,
) -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to create compatibility socket parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let should_replace_existing_path = match std::fs::symlink_metadata(link_path) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() && !allow_replace_compat_socket {
                return Err(anyhow::anyhow!(
                    "existing compatibility socket path is a socket and replacement is disabled: {}",
                    link_path.display()
                ));
            }

            if !metadata.file_type().is_socket() && !metadata.file_type().is_symlink() {
                return Err(anyhow::anyhow!(
                    "existing compatibility socket path is not a socket or symlink: {}",
                    link_path.display()
                ));
            }

            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed to read compatibility socket metadata {}: {error}",
                link_path.display()
            ));
        }
    };

    if should_replace_existing_path {
        cleanup_unix_socket_path(link_path)?;
    }

    let socket_path = if socket_path.is_absolute() {
        socket_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| anyhow::anyhow!("failed to resolve current directory: {error}"))?
            .join(socket_path)
    };

    symlink(&socket_path, link_path).map_err(|error| {
        anyhow::anyhow!(
            "failed to create compatibility socket symlink {} -> {}: {error}",
            link_path.display(),
            socket_path.display()
        )
    })?;

    info!(
        link_path = %link_path.display(),
        socket_path = %socket_path.display(),
        "ipc compatibility socket symlink created"
    );

    Ok(())
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

        let listener = bind_unix_listener(&socket_path, true).unwrap();
        let metadata = std::fs::metadata(&socket_path).unwrap();

        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_listener_fails_when_existing_socket_and_replacement_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");

        let stale_listener = UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let result = bind_unix_listener(&socket_path, false);

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_start_replaces_existing_socket_for_fallback_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("tmp").join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();

        let stale_listener = UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let server = IpcServer::start(&socket_path_str, None, true)
            .await
            .unwrap();
        assert!(socket_path.exists());

        server.shutdown().await.unwrap();
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_accepts_connection_and_shutdown_cleans_up_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let before_count = UNIX_CONNECTION_COUNT.load(std::sync::atomic::Ordering::Relaxed);

        let server = IpcServer::start(&socket_path_str, None, false)
            .await
            .unwrap();
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

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_drop_cleans_up_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let server = IpcServer::start(&socket_path_str, None, false)
            .await
            .unwrap();
        assert!(socket_path.exists());

        drop(server);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_manages_compatibility_symlink_and_cleans_it_up() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent-bridge.sock");
        let compat_path = temp_dir.path().join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let server = IpcServer::start(&socket_path_str, Some(&compat_path), false)
            .await
            .unwrap();

        let metadata = std::fs::symlink_metadata(&compat_path).unwrap();
        assert!(metadata.file_type().is_symlink());

        let target = std::fs::read_link(&compat_path).unwrap();
        assert_eq!(target, socket_path);

        let stream = UnixStream::connect(&compat_path).await.unwrap();
        drop(stream);

        server.shutdown().await.unwrap();

        assert!(!socket_path.exists());
        assert!(!compat_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_start_fails_when_compat_socket_exists_and_replacement_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent-bridge.sock");
        let compat_path = temp_dir.path().join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let stale_listener = UnixListener::bind(&compat_path).unwrap();
        drop(stale_listener);

        let result = IpcServer::start(&socket_path_str, Some(&compat_path), false).await;

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_start_replaces_existing_compat_socket_when_replacement_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent-bridge.sock");
        let compat_path = temp_dir.path().join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let stale_listener = UnixListener::bind(&compat_path).unwrap();
        drop(stale_listener);

        let server = IpcServer::start(&socket_path_str, Some(&compat_path), true)
            .await
            .unwrap();

        let metadata = std::fs::symlink_metadata(&compat_path).unwrap();
        assert!(metadata.file_type().is_symlink());

        let target = std::fs::read_link(&compat_path).unwrap();
        assert_eq!(target, socket_path);

        server.shutdown().await.unwrap();
    }
}
