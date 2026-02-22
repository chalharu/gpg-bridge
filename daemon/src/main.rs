use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-daemon")]
struct Cli {
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(cli.log_level.clone()))
        .with_target(false)
        .compact()
        .init();

    info!(log_level = %cli.log_level, "daemon started");
    info!("waiting for shutdown signal");

    tokio::signal::ctrl_c().await?;

    info!("shutdown signal received");
    Ok(())
}
