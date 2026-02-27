use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const APP_NAME: &str = "gpg-bridge";
const TOKEN_FILE_NAME: &str = "client-token";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TokenEntry {
    pub(crate) client_jwt: String,
    pub(crate) client_id: String,
}

/// Resolve the XDG-compliant token file path.
///
/// - Linux/macOS: `$XDG_CONFIG_HOME/gpg-bridge/client-token`
///   (default: `~/.config/gpg-bridge/client-token`)
/// - Windows: `%APPDATA%\gpg-bridge\client-token`
pub(crate) fn resolve_token_path(lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    resolve_config_dir(lookup).map(|dir| dir.join(TOKEN_FILE_NAME))
}

fn resolve_config_dir(lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        lookup("APPDATA").map(|appdata| PathBuf::from(appdata).join(APP_NAME))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = lookup("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(xdg).join(APP_NAME));
        }
        lookup("HOME").map(|home| PathBuf::from(home).join(".config").join(APP_NAME))
    }
}

/// Load all token entries from the token file.
/// Returns an empty vec if the file doesn't exist.
pub(crate) fn load_tokens(path: &Path) -> anyhow::Result<Vec<TokenEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read token file {}: {e}", path.display()))?;
    let entries: Vec<TokenEntry> = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse token file {}: {e}", path.display()))?;
    Ok(entries)
}

/// Save all token entries to the token file atomically.
///
/// Creates parent directories if needed (0700 on Unix for the app dir).
/// Writes to a temp file (0600 on Unix) then atomically renames to target.
///
/// NOTE: This assumes a single-writer model. Concurrent writers to the same
/// token file are not supported and may result in lost updates.
pub(crate) fn save_tokens(path: &Path, entries: &[TokenEntry]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("token path has no parent directory"))?;
    create_parent_dir(parent)?;
    let content = serde_json::to_string_pretty(entries)
        .map_err(|e| anyhow::anyhow!("failed to serialize tokens: {e}"))?;
    write_atomic(path, parent, content.as_bytes())
}

/// Create the parent directory with appropriate permissions.
fn create_parent_dir(parent: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(parent)
        .map_err(|e| anyhow::anyhow!("failed to create directory {}: {e}", parent.display()))?;
    set_dir_permissions(parent)
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow::anyhow!("failed to set dir permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Write content to target atomically via a temp file in the same directory.
/// The temp file is created with 0600 permissions on Unix (tempfile default).
fn write_atomic(target: &Path, dir: &Path, content: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| anyhow::anyhow!("failed to create temp file in {}: {e}", dir.display()))?;
    tmp.write_all(content)
        .map_err(|e| anyhow::anyhow!("failed to write temp file: {e}"))?;
    tmp.persist(target)
        .map_err(|e| anyhow::anyhow!("failed to atomically replace {}: {e}", target.display()))?;
    Ok(())
}

/// Add or update a token entry in the store.
/// If a token with the same `client_id` exists, it is replaced.
pub(crate) fn upsert_token(path: &Path, entry: TokenEntry) -> anyhow::Result<()> {
    let mut entries = load_tokens(path)?;
    if let Some(existing) = entries.iter_mut().find(|e| e.client_id == entry.client_id) {
        *existing = entry;
    } else {
        entries.push(entry);
    }
    save_tokens(path, &entries)
}

/// Update the JWT for a given client_id. Returns false if client_id was not found.
pub(crate) fn update_jwt(path: &Path, client_id: &str, new_jwt: &str) -> anyhow::Result<bool> {
    let mut entries = load_tokens(path)?;
    let found = entries.iter_mut().find(|e| e.client_id == client_id);
    if let Some(entry) = found {
        entry.client_jwt = new_jwt.to_owned();
        save_tokens(path, &entries)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_token_path_uses_xdg_config_home() {
        let path = resolve_token_path(&|key| match key {
            "XDG_CONFIG_HOME" => Some("/custom/config".into()),
            _ => None,
        });
        assert_eq!(
            path.unwrap(),
            PathBuf::from("/custom/config/gpg-bridge/client-token")
        );
    }

    #[test]
    fn resolve_token_path_falls_back_to_home() {
        let path = resolve_token_path(&|key| match key {
            "HOME" => Some("/home/user".into()),
            _ => None,
        });
        assert_eq!(
            path.unwrap(),
            PathBuf::from("/home/user/.config/gpg-bridge/client-token")
        );
    }

    #[test]
    fn resolve_token_path_returns_none_without_env() {
        let path = resolve_token_path(&|_| None);
        assert!(path.is_none());
    }

    #[test]
    fn load_tokens_returns_empty_for_missing_file() {
        let entries = load_tokens(Path::new("/nonexistent/path/token")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let entries = vec![
            TokenEntry {
                client_jwt: "jwt-a".into(),
                client_id: "id-a".into(),
            },
            TokenEntry {
                client_jwt: "jwt-b".into(),
                client_id: "id-b".into(),
            },
        ];
        save_tokens(&path, &entries).unwrap();
        let loaded = load_tokens(&path).unwrap();
        assert_eq!(loaded, entries);
    }

    #[cfg(unix)]
    #[test]
    fn save_tokens_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        save_tokens(&path, &[]).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_tokens_sets_0700_on_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let app_dir = dir.path().join("myapp");
        let path = app_dir.join("tokens.json");
        save_tokens(&path, &[]).unwrap();
        let meta = std::fs::metadata(&app_dir).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn upsert_token_adds_new_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        upsert_token(
            &path,
            TokenEntry {
                client_jwt: "jwt-1".into(),
                client_id: "id-1".into(),
            },
        )
        .unwrap();
        let loaded = load_tokens(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].client_id, "id-1");
    }

    #[test]
    fn upsert_token_replaces_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        upsert_token(
            &path,
            TokenEntry {
                client_jwt: "old-jwt".into(),
                client_id: "id-1".into(),
            },
        )
        .unwrap();
        upsert_token(
            &path,
            TokenEntry {
                client_jwt: "new-jwt".into(),
                client_id: "id-1".into(),
            },
        )
        .unwrap();
        let loaded = load_tokens(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].client_jwt, "new-jwt");
    }

    #[test]
    fn update_jwt_changes_existing_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        save_tokens(
            &path,
            &[TokenEntry {
                client_jwt: "old".into(),
                client_id: "id-1".into(),
            }],
        )
        .unwrap();
        let updated = update_jwt(&path, "id-1", "refreshed").unwrap();
        assert!(updated);
        let loaded = load_tokens(&path).unwrap();
        assert_eq!(loaded[0].client_jwt, "refreshed");
    }

    #[test]
    fn update_jwt_returns_false_for_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        save_tokens(&path, &[]).unwrap();
        let updated = update_jwt(&path, "unknown", "jwt").unwrap();
        assert!(!updated);
    }

    #[test]
    fn load_tokens_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(&path, "not json").unwrap();
        let result = load_tokens(&path);
        assert!(result.is_err());
    }
}
