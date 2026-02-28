use std::path::Path;
use std::sync::Arc;

use reqwest::Client;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::http::send_post_json_with_retry;
use crate::token_store;

/// A single GPG key entry fetched from the server.
#[derive(Debug, Clone)]
pub(crate) struct GpgKeyEntry {
    pub(crate) keygrip: String,
    #[allow(dead_code)]
    pub(crate) key_id: String,
    pub(crate) public_key: serde_json::Value,
    #[allow(dead_code)]
    pub(crate) client_id: String,
}

/// Volatile in-memory cache for GPG public key information.
///
/// Fetches keys from `POST /pairing/gpg-keys` and caches them behind
/// `Arc<RwLock>` for thread-safe concurrent access.
pub(crate) struct GpgKeyCache {
    entries: RwLock<Option<Vec<GpgKeyEntry>>>,
    http_client: Client,
    server_url: String,
    bearer_header: Option<HeaderValue>,
}

impl std::fmt::Debug for GpgKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpgKeyCache")
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct GpgKeysResponse {
    gpg_keys: Vec<GpgKeyDto>,
}

#[derive(Deserialize)]
struct GpgKeyDto {
    keygrip: String,
    key_id: String,
    public_key: serde_json::Value,
    client_id: String,
}

impl GpgKeyCache {
    /// Create a new cache wrapped in `Arc` for shared ownership.
    pub(crate) fn new(
        http_client: Client,
        server_url: String,
        bearer_header: Option<HeaderValue>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(None),
            http_client,
            server_url,
            bearer_header,
        })
    }

    /// Fetch GPG keys from the server and update the cache.
    pub(crate) async fn refresh(&self, token_store_path: &Path) -> anyhow::Result<()> {
        let tokens = token_store::load_tokens(token_store_path)?;
        let client_jwts: Vec<&str> = tokens.iter().map(|t| t.client_jwt.as_str()).collect();
        let body = serde_json::json!({ "client_jwts": client_jwts });
        let url = format!("{}/pairing/gpg-keys", self.server_url);

        let text =
            send_post_json_with_retry(&self.http_client, &url, self.bearer_header.as_ref(), &body)
                .await?;

        let response: GpgKeysResponse = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse gpg-keys response: {e}"))?;

        let entries = response.gpg_keys.into_iter().map(dto_to_entry).collect();
        *self.entries.write().await = Some(entries);
        Ok(())
    }

    /// Return cached entries, fetching from server if cache is empty.
    pub(crate) async fn get_entries(
        &self,
        token_store_path: &Path,
    ) -> anyhow::Result<Vec<GpgKeyEntry>> {
        {
            let guard = self.entries.read().await;
            if let Some(entries) = &*guard {
                return Ok(entries.clone());
            }
        }
        self.refresh(token_store_path).await?;
        let guard = self.entries.read().await;
        Ok(guard.as_ref().cloned().unwrap_or_default())
    }

    /// Look up a single key entry by keygrip (case-insensitive).
    ///
    /// If the cache is populated but the keygrip is not found, a refresh is
    /// attempted before returning `None` (requirements 7.1.2 / 10.4).
    pub(crate) async fn find_by_keygrip(
        &self,
        keygrip: &str,
        token_store_path: &Path,
    ) -> anyhow::Result<Option<GpgKeyEntry>> {
        let entries = self.get_entries(token_store_path).await?;
        if let Some(entry) = entries
            .iter()
            .find(|e| e.keygrip.eq_ignore_ascii_case(keygrip))
        {
            return Ok(Some(entry.clone()));
        }
        // Cache was populated but key not found — re-fetch and try once more.
        if let Err(err) = self.refresh(token_store_path).await {
            tracing::warn!(?err, "cache-miss refresh failed for find_by_keygrip");
            return Ok(None);
        }
        let entries = self.get_entries(token_store_path).await?;
        Ok(entries
            .into_iter()
            .find(|e| e.keygrip.eq_ignore_ascii_case(keygrip)))
    }

    /// Check if any of the given keygrips exist in the cache (case-insensitive).
    ///
    /// If the cache is populated but no match is found, a refresh is attempted
    /// before returning `false` (requirements 7.1.2 / 10.4).
    pub(crate) async fn has_any_keygrip(
        &self,
        keygrips: &[String],
        token_store_path: &Path,
    ) -> anyhow::Result<bool> {
        let entries = self.get_entries(token_store_path).await?;
        if entries
            .iter()
            .any(|e| keygrips.iter().any(|kg| e.keygrip.eq_ignore_ascii_case(kg)))
        {
            return Ok(true);
        }
        // Cache was populated but no match — re-fetch and try once more.
        if let Err(err) = self.refresh(token_store_path).await {
            tracing::warn!(?err, "cache-miss refresh failed for has_any_keygrip");
            return Ok(false);
        }
        let entries = self.get_entries(token_store_path).await?;
        Ok(entries
            .iter()
            .any(|e| keygrips.iter().any(|kg| e.keygrip.eq_ignore_ascii_case(kg))))
    }
}

fn dto_to_entry(dto: GpgKeyDto) -> GpgKeyEntry {
    GpgKeyEntry {
        keygrip: dto.keygrip,
        key_id: dto.key_id,
        public_key: dto.public_key,
        client_id: dto.client_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> Arc<GpgKeyCache> {
        GpgKeyCache::new(Client::new(), "http://localhost:0".to_owned(), None)
    }

    #[tokio::test]
    async fn get_entries_returns_empty_when_no_token_file() {
        let cache = make_cache();
        // With a non-existent token file, load_tokens returns empty vec,
        // then the POST will fail (no server). We rely on the error path.
        let result = cache
            .get_entries(Path::new("/nonexistent/path/tokens"))
            .await;
        // The HTTP call will fail because there's no server, that's expected
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cache_returns_stored_entries_without_refetch() {
        let cache = make_cache();
        let entries = vec![GpgKeyEntry {
            keygrip: "ABC123".to_owned(),
            key_id: "key-1".to_owned(),
            public_key: serde_json::json!({}),
            client_id: "client-1".to_owned(),
        }];
        *cache.entries.write().await = Some(entries);

        let result = cache.get_entries(Path::new("/nonexistent")).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].keygrip, "ABC123");
    }

    #[tokio::test]
    async fn find_by_keygrip_case_insensitive() {
        let cache = make_cache();
        *cache.entries.write().await = Some(vec![GpgKeyEntry {
            keygrip: "AABB".to_owned(),
            key_id: "k1".to_owned(),
            public_key: serde_json::json!({}),
            client_id: "c1".to_owned(),
        }]);

        let found = cache
            .find_by_keygrip("aabb", Path::new("/x"))
            .await
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn find_by_keygrip_returns_none_when_not_found() {
        let cache = make_cache();
        *cache.entries.write().await = Some(vec![]);

        let found = cache
            .find_by_keygrip("DEAD", Path::new("/x"))
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn has_any_keygrip_returns_true_when_match() {
        let cache = make_cache();
        *cache.entries.write().await = Some(vec![GpgKeyEntry {
            keygrip: "AABB".to_owned(),
            key_id: "k1".to_owned(),
            public_key: serde_json::json!({}),
            client_id: "c1".to_owned(),
        }]);

        let has = cache
            .has_any_keygrip(&["ccdd".to_owned(), "aabb".to_owned()], Path::new("/x"))
            .await
            .unwrap();
        assert!(has);
    }

    #[tokio::test]
    async fn has_any_keygrip_returns_false_when_no_match() {
        let cache = make_cache();
        *cache.entries.write().await = Some(vec![GpgKeyEntry {
            keygrip: "AABB".to_owned(),
            key_id: "k1".to_owned(),
            public_key: serde_json::json!({}),
            client_id: "c1".to_owned(),
        }]);

        let has = cache
            .has_any_keygrip(&["ccdd".to_owned()], Path::new("/x"))
            .await
            .unwrap();
        assert!(!has);
    }

    #[tokio::test]
    async fn refresh_populates_cache_from_server() {
        use crate::http::build_http_client;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Prepare a token file so load_tokens returns a JWT.
        let tmp_dir = std::env::temp_dir().join("gpg-bridge-test-refresh");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let token_path = tmp_dir.join("client-token");
        std::fs::write(
            &token_path,
            r#"[{"client_jwt":"test-jwt","client_id":"cid-1"}]"#,
        )
        .unwrap();

        let response_body = serde_json::json!({
            "gpg_keys": [
                {
                    "keygrip": "AABBCCDD",
                    "key_id": "key-1",
                    "public_key": { "kty": "RSA" },
                    "client_id": "cid-1"
                }
            ]
        })
        .to_string();

        let server = tokio::spawn({
            let body = response_body.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let client = build_http_client(Duration::from_secs(2), "test/1.0").unwrap();
        let cache = GpgKeyCache::new(client, format!("http://{addr}"), None);

        cache.refresh(&token_path).await.unwrap();

        let entries = cache.entries.read().await;
        let entries = entries.as_ref().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].keygrip, "AABBCCDD");
        assert_eq!(entries[0].key_id, "key-1");
        assert_eq!(entries[0].client_id, "cid-1");

        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
