use clap::Parser;
use gpg_bridge_server::{
    config::AppConfig,
    http::{
        AppState, build_router,
        fcm::{self, FcmSender, FcmValidator, NoopFcmSender, NoopFcmValidator},
        pairing::notifier::PairingNotifier,
        rate_limit::{RateLimitConfig, SseConnectionTracker, config::SseConnectionConfig},
        signing::notifier::SignEventNotifier,
    },
    observability::init_tracing,
    repository::build_repository,
};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "gpg-bridge-server")]
struct Cli {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
}

fn parse_cli_from<I, T>(args: I) -> Cli
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::parse_from(args)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    let cli = parse_cli_from(std::env::args_os());
    let config = AppConfig::from_env()?;
    init_tracing(&config)?;

    let host = cli.host.unwrap_or_else(|| config.server_host.clone());
    let port = cli.port.unwrap_or(config.server_port);

    let repository = build_repository(&config).await?;
    repository.run_migrations().await?;
    repository.health_check().await?;

    let (fcm_validator, fcm_sender) = build_fcm_clients(&config)?;

    let state = AppState {
        repository,
        base_url: config.base_url.clone(),
        signing_key_secret: config.signing_key_secret.clone(),
        device_jwt_validity_seconds: config.device_jwt_validity_seconds,
        pairing_jwt_validity_seconds: config.pairing_jwt_validity_seconds,
        client_jwt_validity_seconds: config.client_jwt_validity_seconds,
        request_jwt_validity_seconds: config.request_jwt_validity_seconds,
        unconsumed_pairing_limit: config.unconsumed_pairing_limit,
        fcm_validator,
        fcm_sender,
        sse_tracker: SseConnectionTracker::new(SseConnectionConfig {
            max_per_ip: config.rate_limit_sse_max_per_ip,
            max_per_key: config.rate_limit_sse_max_per_key,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: SignEventNotifier::new(),
    };
    let rate_limit_config = RateLimitConfig::from_app_config(&config);
    let app = build_router(state, rate_limit_config);
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    let addr = listener.local_addr()?;

    info!(%addr, "server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

type FcmClients = (Arc<dyn FcmValidator>, Arc<dyn FcmSender>);

fn build_fcm_clients(config: &AppConfig) -> Result<FcmClients, Box<dyn std::error::Error>> {
    match (&config.fcm_service_account_key_path, &config.fcm_project_id) {
        (Some(key_path), Some(project_id)) => {
            let client = fcm::build_fcm_client(key_path, project_id)?;
            let arc_client = Arc::new(client);
            info!("FCM enabled (project: {project_id})");
            Ok((arc_client.clone(), arc_client))
        }
        (Some(_), None) => {
            warn!(
                "Partial FCM config: fcm_service_account_key_path is set but fcm_project_id is missing; falling back to Noop"
            );
            Ok((Arc::new(NoopFcmValidator), Arc::new(NoopFcmSender)))
        }
        (None, Some(_)) => {
            warn!(
                "Partial FCM config: fcm_project_id is set but fcm_service_account_key_path is missing; falling back to Noop"
            );
            Ok((Arc::new(NoopFcmValidator), Arc::new(NoopFcmSender)))
        }
        (None, None) => {
            info!("FCM disabled (no credentials configured)");
            Ok((Arc::new(NoopFcmValidator), Arc::new(NoopFcmSender)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-server"]);

        assert_eq!(cli.host, None);
        assert_eq!(cli.port, None);
    }

    #[test]
    fn cli_custom_values_are_applied() {
        let cli = parse_cli_from(["gpg-bridge-server", "--host", "0.0.0.0", "--port", "8080"]);

        assert_eq!(cli.host, Some("0.0.0.0".to_owned()));
        assert_eq!(cli.port, Some(8080));
    }

    #[test]
    fn parse_cli_from_accepts_short_args_array() {
        let cli = parse_cli_from(["gpg-bridge-server", "--port", "3001"]);

        assert_eq!(cli.host, None);
        assert_eq!(cli.port, Some(3001));
    }

    fn test_config(fcm_key_path: Option<&str>, fcm_project_id: Option<&str>) -> AppConfig {
        AppConfig::from_lookup(&|key| match key {
            "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
            "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
            "SERVER_FCM_SERVICE_ACCOUNT_KEY_PATH" => fcm_key_path.map(String::from),
            "SERVER_FCM_PROJECT_ID" => fcm_project_id.map(String::from),
            _ => None,
        })
        .unwrap()
    }

    #[test]
    fn build_fcm_clients_noop_when_no_config() {
        let config = test_config(None, None);
        let (validator, sender) = build_fcm_clients(&config).unwrap();
        // Noop validator/sender should succeed without hitting any real API
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(validator.validate_token("tok")).unwrap());
        rt.block_on(sender.send_data_message("tok", &serde_json::json!({})))
            .unwrap();
    }

    #[test]
    fn build_fcm_clients_noop_when_only_key_path() {
        let config = test_config(Some("/some/key.json"), None);
        // Should fall back to Noop (partial config)
        let (validator, _sender) = build_fcm_clients(&config).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(validator.validate_token("tok")).unwrap());
    }

    #[test]
    fn build_fcm_clients_noop_when_only_project_id() {
        let config = test_config(None, Some("my-project"));
        // Should fall back to Noop (partial config)
        let (validator, _sender) = build_fcm_clients(&config).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(validator.validate_token("tok")).unwrap());
    }

    #[test]
    fn build_fcm_clients_real_when_full_config() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("sa.json");
        let sa_json = serde_json::json!({
            "client_email": "test@proj.iam.gserviceaccount.com",
            "private_key": include_str!("../test_fixtures/fake_rsa_key.pem"),
            "token_uri": "https://oauth2.googleapis.com/token"
        });
        std::fs::write(&key_path, sa_json.to_string()).unwrap();
        let config = test_config(key_path.to_str(), Some("my-project"));
        let result = build_fcm_clients(&config);
        assert!(result.is_ok());
    }
}
