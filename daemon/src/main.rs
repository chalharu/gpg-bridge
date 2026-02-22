use clap::Parser;
use std::future::Future;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-daemon")]
struct Cli {
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn parse_cli_from<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::parse_from(args)
}

fn build_env_filter(log_level: &str) -> anyhow::Result<EnvFilter> {
    Ok(EnvFilter::try_new(log_level.to_owned())?)
}

fn setup_tracing(log_level: &str) -> anyhow::Result<()> {
    let env_filter = build_env_filter(log_level)?;

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
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
    setup_tracing(&cli.log_level)?;

    info!(log_level = %cli.log_level, "daemon started");
    info!("waiting for shutdown signal");

    wait_for_shutdown_signal(tokio::signal::ctrl_c()).await?;

    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-daemon"]);

        assert_eq!(cli.log_level, "info");
    }

    #[test]
    fn cli_custom_log_level_is_applied() {
        let cli = parse_cli_from(["gpg-bridge-daemon", "--log-level", "debug"]);

        assert_eq!(cli.log_level, "debug");
    }

    #[test]
    fn build_env_filter_accepts_valid_log_level() {
        let result = build_env_filter("debug");

        assert!(result.is_ok());
    }

    #[test]
    fn build_env_filter_rejects_invalid_log_level() {
        let result = build_env_filter("debug[");

        assert!(result.is_err());
    }

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
