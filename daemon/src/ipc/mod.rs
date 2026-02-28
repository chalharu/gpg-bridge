#[cfg(unix)]
mod unix;
#[cfg(any(windows, test))]
mod windows;

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::path::Path;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::warn;

/// Short delay before retrying after a transient accept error (e.g., EMFILE/ENFILE).
pub(super) const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

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
        context: Arc<crate::assuan::SessionContext>,
    ) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_server(
            endpoint,
            compat_socket_path.map(Path::to_path_buf),
            allow_replace_existing_socket,
            shutdown_rx,
            context,
        )?;

        Ok(Self {
            task: Some(task),
            shutdown_tx,
            socket_path: PathBuf::from(endpoint),
            compat_socket_path: compat_socket_path.map(Path::to_path_buf),
        })
    }

    #[cfg(windows)]
    pub async fn start(
        endpoint: &str,
        context: Arc<crate::assuan::SessionContext>,
    ) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_server(endpoint, shutdown_rx, context)?;

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
    /// Safety-net cleanup: sends shutdown signal, aborts the task, and removes socket files.
    /// The spawned task also performs cleanup on normal exit. This intentional double-cleanup
    /// design ensures sockets are removed even if the task is cancelled or panics.
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }

        #[cfg(unix)]
        if let Err(error) = unix::cleanup_unix_socket_path(&self.socket_path) {
            warn!(socket_path = %self.socket_path.display(), ?error, "failed to cleanup unix socket file on drop");
        }

        #[cfg(unix)]
        if let Some(path) = &self.compat_socket_path
            && let Err(error) = unix::cleanup_unix_socket_path(path)
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
    context: Arc<crate::assuan::SessionContext>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let socket_path = PathBuf::from(endpoint);
    let listener = unix::bind_unix_listener(&socket_path, allow_replace_existing_socket)?;
    if let Some(path) = compat_socket_path.as_deref() {
        unix::create_unix_socket_symlink(path, &socket_path, allow_replace_existing_socket)?;
    }

    Ok(tokio::spawn(async move {
        let run_result = unix::run_unix_accept_loop(listener, shutdown_rx, context).await;
        if let Err(error) = unix::cleanup_unix_socket_path(&socket_path) {
            warn!(socket_path = %socket_path.display(), ?error, "failed to cleanup unix socket file");
        }
        if let Some(path) = compat_socket_path
            && let Err(error) = unix::cleanup_unix_socket_path(&path)
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
    context: Arc<crate::assuan::SessionContext>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let pipe_name = windows::normalize_pipe_name(endpoint);

    Ok(tokio::spawn(async move {
        windows::run_windows_accept_loop(&pipe_name, shutdown_rx, context).await
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use tokio::net::UnixStream;

    #[cfg(unix)]
    fn test_context(socket_path_str: &str) -> Arc<crate::assuan::SessionContext> {
        let cache = crate::gpg_key_cache::GpgKeyCache::new(
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
            None,
        );
        Arc::new(crate::assuan::SessionContext::new(
            socket_path_str,
            cache,
            std::path::PathBuf::from("/tmp/test-tokens"),
            reqwest::Client::new(),
            "http://localhost:0".to_owned(),
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_start_replaces_existing_socket_for_fallback_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("tmp").join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();

        let stale_listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let context = test_context(&socket_path_str);
        let server = IpcServer::start(&socket_path_str, None, true, context)
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

        let before_count = unix::UNIX_CONNECTION_COUNT.load(std::sync::atomic::Ordering::Relaxed);

        let context = test_context(&socket_path_str);
        let server = IpcServer::start(&socket_path_str, None, false, context)
            .await
            .unwrap();
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        drop(stream);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let current =
                    unix::UNIX_CONNECTION_COUNT.load(std::sync::atomic::Ordering::Relaxed);
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

        let context = test_context(&socket_path_str);
        let server = IpcServer::start(&socket_path_str, None, false, context)
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

        let context = test_context(&socket_path_str);
        let server = IpcServer::start(&socket_path_str, Some(&compat_path), false, context)
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

        let stale_listener = tokio::net::UnixListener::bind(&compat_path).unwrap();
        drop(stale_listener);

        let result = IpcServer::start(
            &socket_path_str,
            Some(&compat_path),
            false,
            test_context(&socket_path_str),
        )
        .await;

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipc_server_start_replaces_existing_compat_socket_when_replacement_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent-bridge.sock");
        let compat_path = temp_dir.path().join("S.gpg-agent");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let stale_listener = tokio::net::UnixListener::bind(&compat_path).unwrap();
        drop(stale_listener);

        let context = test_context(&socket_path_str);
        let server = IpcServer::start(&socket_path_str, Some(&compat_path), true, context)
            .await
            .unwrap();

        let metadata = std::fs::symlink_metadata(&compat_path).unwrap();
        assert!(metadata.file_type().is_symlink());

        let target = std::fs::read_link(&compat_path).unwrap();
        assert_eq!(target, socket_path);

        server.shutdown().await.unwrap();
    }
}
