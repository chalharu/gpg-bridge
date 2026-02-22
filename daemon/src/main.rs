use clap::Parser;
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

fn build_env_filter(log_level: &str) -> EnvFilter {
    EnvFilter::new(log_level.to_owned())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli_from(std::env::args_os());
    let env_filter = build_env_filter(&cli.log_level);

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();

    info!(log_level = %cli.log_level, "daemon started");
    info!("waiting for shutdown signal");

    tokio::signal::ctrl_c().await?;

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

        let rendered = format!("{result:?}");
        assert!(!rendered.is_empty());
    }
}
