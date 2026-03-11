use super::*;
use std::io::Write;
use tempfile::Builder;

fn load_temp_file_config(suffix: &str, contents: &str) -> FileConfig {
    let mut file = Builder::new().suffix(suffix).tempfile().unwrap();
    write!(file, "{contents}").unwrap();
    load_file_config(Some(file.path())).unwrap()
}

fn assert_basic_file_config(config: FileConfig, log_level: &str) {
    assert_eq!(config.server_url, Some("https://daemon.example".to_owned()));
    assert_eq!(config.socket_path, Some("tmp/daemon.sock".to_owned()));
    assert_eq!(config.log_level, Some(log_level.to_owned()));
}

fn sample_file_config() -> FileConfig {
    FileConfig {
        server_url: Some("https://file.example".to_owned()),
        socket_path: Some("tmp/file.sock".to_owned()),
        log_level: Some("warn".to_owned()),
        kill_existing_agent: None,
    }
}

fn sample_env_lookup(key: &str) -> Option<String> {
    match key {
        "DAEMON_SERVER_URL" => Some("https://env.example".to_owned()),
        "DAEMON_SOCKET_PATH" => Some("tmp/env.sock".to_owned()),
        "DAEMON_LOG_LEVEL" => Some("debug".to_owned()),
        _ => None,
    }
}

fn assert_supported_file_config_parses(suffix: &str, contents: &str, log_level: &str) {
    let config = load_temp_file_config(suffix, contents);
    assert_basic_file_config(config, log_level);
}

fn assert_runtime_config(
    config: AppConfig,
    server_url: &str,
    socket_path: &str,
    log_level: &str,
    kill_existing_agent: bool,
) {
    assert_eq!(config.server_url, server_url);
    assert_eq!(config.socket_path, socket_path);
    assert_eq!(config.log_level, log_level);
    assert_eq!(config.kill_existing_agent, kill_existing_agent);
    assert!(config.allow_replace_existing_socket);
}

#[test]
fn cli_defaults_are_applied() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);

    assert!(cli.log_level.is_none());
    assert!(cli.server_url.is_none());
    assert!(cli.socket_path.is_none());
    assert!(cli.config_path.is_none());
    assert!(!cli.kill_existing_agent);
}

#[test]
fn cli_custom_log_level_is_applied() {
    let cli = parse_cli_from([
        "gpg-bridge-daemon",
        "--server-url",
        "https://example.com",
        "--socket-path",
        "tmp/socket",
        "--config-path",
        "tmp/config.toml",
        "--log-level",
        "debug",
        "--kill-existing-agent",
    ]);

    assert_eq!(cli.log_level, Some("debug".to_owned()));
    assert_eq!(cli.server_url, Some("https://example.com".to_owned()));
    assert_eq!(cli.socket_path, Some("tmp/socket".to_owned()));
    assert_eq!(cli.config_path, Some(PathBuf::from("tmp/config.toml")));
    assert!(cli.kill_existing_agent);
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

#[test]
fn parse_toml_file_config() {
    assert_supported_file_config_parses(
        ".toml",
        "server_url = 'https://daemon.example'\nsocket_path = 'tmp/daemon.sock'\nlog_level = 'debug'\n",
        "debug",
    );
}

#[test]
fn parse_yaml_file_config() {
    assert_supported_file_config_parses(
        ".yaml",
        "server_url: https://daemon.example\nsocket_path: tmp/daemon.sock\nlog_level: warn\n",
        "warn",
    );
}

#[test]
fn cli_overrides_env_and_file_config() {
    let cli = parse_cli_from([
        "gpg-bridge-daemon",
        "--server-url",
        "https://cli.example",
        "--socket-path",
        "tmp/cli.sock",
        "--log-level",
        "error",
    ]);

    let file = sample_file_config();

    let config = build_app_config(&cli, &file, &sample_env_lookup, None).unwrap();

    assert_runtime_config(
        config,
        "https://cli.example",
        "tmp/cli.sock",
        "error",
        false,
    );
}

#[test]
fn env_overrides_file_config() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);
    let file = sample_file_config();

    let config = build_app_config(&cli, &file, &sample_env_lookup, None).unwrap();

    assert_runtime_config(
        config,
        "https://env.example",
        "tmp/env.sock",
        "debug",
        false,
    );
}

#[test]
fn build_app_config_rejects_invalid_server_url() {
    let cli = parse_cli_from(["gpg-bridge-daemon", "--server-url", "localhost:3000"]);
    let file = FileConfig::default();
    let lookup = |_key: &str| None;

    let result = build_app_config(&cli, &file, &lookup, None);
    assert!(result.is_err());
}

#[test]
fn build_app_config_uses_detected_socket_when_not_set_elsewhere() {
    let cli = parse_cli_from(["gpg-bridge-daemon", "--kill-existing-agent"]);
    let file = FileConfig::default();
    let lookup = |_key: &str| None;

    let config = build_app_config(&cli, &file, &lookup, Some("/tmp/gnupg/S.gpg-agent")).unwrap();

    assert_eq!(config.socket_path, "/tmp/gnupg/S.gpg-agent");
    assert!(config.allow_replace_existing_socket);
}

#[test]
fn build_app_config_fallback_socket_allows_existing_socket_replacement() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);
    let file = FileConfig::default();
    let lookup = |key: &str| match key {
        "HOME" => Some("/home/testuser".to_owned()),
        _ => None,
    };

    let config = build_app_config(&cli, &file, &lookup, Some("/tmp/gnupg/S.gpg-agent")).unwrap();

    assert_eq!(config.socket_path, "/home/testuser/.gnupg/S.gpg-agent");
    assert!(config.allow_replace_existing_socket);
}

#[test]
fn build_app_config_applies_kill_existing_agent_from_env_and_file() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);
    let file = FileConfig {
        kill_existing_agent: Some(false),
        ..FileConfig::default()
    };

    let lookup = |key: &str| match key {
        "DAEMON_KILL_EXISTING_AGENT" => Some("true".to_owned()),
        _ => None,
    };

    let config = build_app_config(&cli, &file, &lookup, None).unwrap();
    assert!(config.kill_existing_agent);
    assert!(config.allow_replace_existing_socket);
}

#[test]
fn build_app_config_allows_existing_socket_replacement_for_explicit_socket_path() {
    let cli = parse_cli_from(["gpg-bridge-daemon", "--socket-path", "tmp/explicit.sock"]);
    let file = FileConfig::default();
    let lookup = |_key: &str| None;

    let config = build_app_config(&cli, &file, &lookup, None).unwrap();

    assert_eq!(config.socket_path, "tmp/explicit.sock");
    assert!(config.allow_replace_existing_socket);
}

#[cfg(unix)]
#[test]
fn resolve_compat_socket_path_returns_none_when_detected_is_none() {
    let result = resolve_compat_socket_path("/tmp/custom.sock", None);
    assert!(result.is_none());
}

#[cfg(unix)]
#[test]
fn resolve_compat_socket_path_returns_none_when_paths_are_equal() {
    let result = resolve_compat_socket_path("/tmp/S.gpg-agent", Some("/tmp/S.gpg-agent"));
    assert!(result.is_none());
}

#[cfg(unix)]
#[test]
fn resolve_compat_socket_path_returns_detected_when_paths_differ() {
    let result = resolve_compat_socket_path("/tmp/custom.sock", Some("/tmp/S.gpg-agent"));
    assert_eq!(result, Some(PathBuf::from("/tmp/S.gpg-agent")));
}

#[test]
fn fallback_socket_path_uses_home_env() {
    let lookup = |key: &str| match key {
        "HOME" => Some("/home/testuser".to_owned()),
        _ => None,
    };
    assert_eq!(
        fallback_socket_path(&lookup),
        "/home/testuser/.gnupg/S.gpg-agent"
    );
}

#[test]
fn fallback_socket_path_uses_tmp_when_no_home() {
    let lookup = |_key: &str| None;
    assert_eq!(fallback_socket_path(&lookup), "/tmp/gpg-bridge/S.gpg-agent");
}

#[test]
fn resolve_config_path_returns_cli_path_when_set() {
    let cli = parse_cli_from(["gpg-bridge-daemon", "--config-path", "/etc/daemon.toml"]);
    let lookup = |_key: &str| None;
    let result = resolve_config_path(&cli, &lookup);
    assert_eq!(result, Some(PathBuf::from("/etc/daemon.toml")));
}

#[test]
fn resolve_config_path_returns_env_path_when_cli_unset() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);
    let lookup = |key: &str| match key {
        "DAEMON_CONFIG_PATH" => Some("/etc/daemon-env.toml".to_owned()),
        _ => None,
    };
    let result = resolve_config_path(&cli, &lookup);
    assert_eq!(result, Some(PathBuf::from("/etc/daemon-env.toml")));
}

#[test]
fn resolve_config_path_returns_none_when_unset() {
    let cli = parse_cli_from(["gpg-bridge-daemon"]);
    let lookup = |_key: &str| None;
    let result = resolve_config_path(&cli, &lookup);
    assert!(result.is_none());
}
