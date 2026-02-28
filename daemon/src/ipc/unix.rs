use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{info, warn};

use super::ACCEPT_ERROR_BACKOFF;

pub(super) fn bind_unix_listener(
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

pub(super) fn cleanup_unix_socket_path(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "failed to remove unix socket {}: {error}",
            path.display()
        )),
    }
}

pub(super) fn create_unix_socket_symlink(
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

pub(super) async fn run_unix_accept_loop(
    listener: tokio::net::UnixListener,
    mut shutdown_rx: watch::Receiver<bool>,
    context: Arc<crate::assuan::SessionContext>,
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
                let (stream, _) = match accepted {
                    Ok(conn) => conn,
                    Err(error) => {
                        warn!(?error, "failed to accept unix socket connection");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                info!("ipc unix socket connection accepted");
                let ctx = Arc::clone(&context);
                tokio::spawn(async move {
                    if let Err(error) = handle_unix_connection(stream, ctx).await {
                        warn!(?error, "ipc unix socket connection handler failed");
                    }
                });
            }
        }
    }
}

async fn handle_unix_connection(
    stream: tokio::net::UnixStream,
    context: Arc<crate::assuan::SessionContext>,
) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        UNIX_CONNECTION_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    crate::assuan::run_session(stream, &context).await
}

#[cfg(test)]
pub(super) static UNIX_CONNECTION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

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

    #[tokio::test]
    async fn bind_unix_listener_fails_when_existing_socket_and_replacement_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");

        let stale_listener = UnixListener::bind(&socket_path).unwrap();
        drop(stale_listener);

        let result = bind_unix_listener(&socket_path, false);

        assert!(result.is_err());
    }
}
