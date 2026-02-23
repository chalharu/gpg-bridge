use tokio::process::Command;

fn parse_gpgconf_agent_socket_output(output: &str) -> anyhow::Result<String> {
    let socket_path = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("gpgconf returned empty agent socket path"))?;

    if socket_path == "0" {
        return Err(anyhow::anyhow!(
            "gpgconf returned unavailable marker for agent socket path"
        ));
    }

    Ok(socket_path.to_owned())
}

pub(crate) async fn detect_gpg_agent_socket_path() -> anyhow::Result<String> {
    let output = Command::new("gpgconf")
        .args(["--list-dirs", "agent-socket"])
        .output()
        .await
        .map_err(|error| {
            anyhow::anyhow!("failed to run gpgconf --list-dirs agent-socket: {error}")
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(anyhow::anyhow!(
            "gpgconf --list-dirs agent-socket failed: {}",
            if stderr.is_empty() {
                format!("exit status {}", output.status)
            } else {
                stderr
            }
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| anyhow::anyhow!("gpgconf output is not valid UTF-8: {error}"))?;

    parse_gpgconf_agent_socket_output(&stdout)
}

pub(crate) async fn kill_existing_gpg_agent() -> anyhow::Result<()> {
    let output = Command::new("gpgconf")
        .args(["--kill", "gpg-agent"])
        .output()
        .await
        .map_err(|error| anyhow::anyhow!("failed to run gpgconf --kill gpg-agent: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(anyhow::anyhow!(
        "gpgconf --kill gpg-agent failed: {}",
        if stderr.is_empty() {
            format!("exit status {}", output.status)
        } else {
            stderr
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gpgconf_agent_socket_output_parses_first_non_empty_line() {
        let result = parse_gpgconf_agent_socket_output("\n  /tmp/gnupg/S.gpg-agent\n").unwrap();

        assert_eq!(result, "/tmp/gnupg/S.gpg-agent");
    }

    #[test]
    fn parse_gpgconf_agent_socket_output_rejects_unavailable_marker() {
        let result = parse_gpgconf_agent_socket_output("0\n");

        assert!(result.is_err());
    }
}
