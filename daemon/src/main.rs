use std::future::Future;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};

mod assuan;
mod config;
mod gpg;
mod http;
mod ipc;
// Pairing flow, token storage, and token refresh modules are ready for
// integration once CLI subcommand support is added.
// TODO(KAN-38): Remove #[allow(dead_code)] when these modules are wired into CLI subcommands.
#[allow(dead_code)]
mod pairing;
mod sse;
#[allow(dead_code)]
mod token_refresh;
#[allow(dead_code)]
mod token_store;

use config::{
    build_app_config, load_file_config, parse_cli_from, resolve_config_path, setup_tracing,
};
use gpg::{detect_gpg_agent_socket_path, kill_existing_gpg_agent};
use http::{
    DEFAULT_HTTP_TIMEOUT_SECONDS, MAX_HTTP_RETRIES, build_bearer_header, build_http_client,
};
use sse::{DaemonSseEvent, SseClient, SseClientConfig};

fn default_user_agent() -> String {
    format!("gpg-bridge-daemon/{}", env!("CARGO_PKG_VERSION"))
}

async fn wait_for_shutdown_signal<F>(shutdown_signal: F) -> anyhow::Result<()>
where
    F: Future<Output = std::io::Result<()>>,
{
    shutdown_signal.await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli_from(std::env::args_os());
    let lookup = |key: &str| std::env::var(key).ok();
    let config_path = resolve_config_path(&cli, &lookup);
    let file_config = load_file_config(config_path.as_deref())?;
    let detected_default_socket_path = detect_gpg_agent_socket_path().await;
    let config = build_app_config(
        &cli,
        &file_config,
        &lookup,
        detected_default_socket_path.as_deref().ok(),
    )?;
    let http_client = build_http_client(
        Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECONDS),
        &default_user_agent(),
    )?;

    setup_tracing(&config.log_level)?;

    if let Err(error) = detected_default_socket_path {
        warn!(
            ?error,
            "failed to detect default gpg-agent socket path via gpgconf; using fallback resolution"
        );
    }

    if config.kill_existing_agent {
        kill_existing_gpg_agent().await?;
        info!("requested existing gpg-agent stop via gpgconf");
    }

    let _bearer_header = if let Some(token) = lookup("DAEMON_ACCESS_TOKEN") {
        Some(build_bearer_header(&token)?)
    } else {
        None
    };

    info!(
        log_level = %config.log_level,
        server_url = %config.server_url,
        socket_path = %config.socket_path,
        allow_replace_existing_socket = config.allow_replace_existing_socket,
        http_timeout_seconds = DEFAULT_HTTP_TIMEOUT_SECONDS,
        max_http_retries = MAX_HTTP_RETRIES,
        kill_existing_agent = config.kill_existing_agent,
        "daemon started"
    );

    #[cfg(unix)]
    let ipc_server = ipc::IpcServer::start(
        &config.socket_path,
        config.compat_socket_path.as_deref(),
        config.allow_replace_existing_socket,
    )
    .await?;

    #[cfg(windows)]
    let ipc_server = ipc::IpcServer::start(&config.socket_path).await?;

    let (sse_shutdown_tx, sse_task) = if let Some(sse_url) = lookup("DAEMON_SSE_URL") {
        let sse_client = SseClient::new(http_client.clone(), SseClientConfig::new(sse_url))?;
        let (tx, rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            let run_result = sse_client
                .run_with_handler(rx, |event| async move {
                    match event {
                        DaemonSseEvent::Heartbeat => {
                            info!("sse heartbeat");
                        }
                        DaemonSseEvent::Message {
                            event_type,
                            id,
                            data,
                        } => {
                            info!(event_type = %event_type, event_id = ?id, data = %data, "sse event received");
                        }
                    }

                    Ok(())
                })
                .await;

            if let Err(error) = run_result {
                tracing::warn!(?error, "sse client stopped");
            }
        });

        (Some(tx), Some(task))
    } else {
        (None, None)
    };

    info!("waiting for shutdown signal");

    let shutdown_signal_result = wait_for_shutdown_signal(tokio::signal::ctrl_c()).await;

    if let Some(tx) = sse_shutdown_tx {
        let _ = tx.send(true);
    }
    if let Some(task) = sse_task {
        let _ = task.await;
    }

    ipc_server.shutdown().await?;

    shutdown_signal_result?;

    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_for_shutdown_signal_succeeds_when_signal_succeeds() {
        let result = wait_for_shutdown_signal(async { Ok(()) }).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_shutdown_signal_returns_error_when_signal_fails() {
        let result = wait_for_shutdown_signal(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "signal error",
            ))
        })
        .await;

        assert!(result.is_err());
    }
}
