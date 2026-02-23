use reqwest::{
    Client, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER},
};
use std::time::Duration;

pub(crate) const DEFAULT_HTTP_TIMEOUT_SECONDS: u64 = 10;
pub(crate) const MAX_HTTP_RETRIES: u32 = 3;

pub(crate) fn build_http_client(timeout: Duration, user_agent: &str) -> anyhow::Result<Client> {
    let client = Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .build()?;

    Ok(client)
}

pub(crate) fn build_bearer_header(token: &str) -> anyhow::Result<HeaderValue> {
    if token.trim().is_empty() {
        return Err(anyhow::anyhow!("bearer token must not be empty"));
    }

    Ok(HeaderValue::from_str(&format!("Bearer {token}"))?)
}

// HTTP utility functions used by tests and the upcoming Assuan protocol handler.
#[allow(dead_code)]
pub(crate) fn retry_delay_for(
    status: StatusCode,
    headers: &HeaderMap,
    attempt: u32,
) -> Option<Duration> {
    if attempt >= MAX_HTTP_RETRIES {
        return None;
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return headers
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .or_else(|| Some(Duration::from_secs(u64::from(attempt + 1))));
    }

    if status.is_server_error() {
        return Some(Duration::from_secs(2_u64.pow(attempt)));
    }

    None
}

#[allow(dead_code)]
pub(crate) fn map_status_error(status: StatusCode, url: &str) -> anyhow::Error {
    match status {
        StatusCode::UNAUTHORIZED => anyhow::anyhow!("authentication failed for {url} (401)"),
        StatusCode::FORBIDDEN => anyhow::anyhow!("permission denied for {url} (403)"),
        StatusCode::NOT_FOUND => anyhow::anyhow!("resource not found at {url} (404)"),
        StatusCode::TOO_MANY_REQUESTS => anyhow::anyhow!("rate limited by {url} (429)"),
        _ if status.is_server_error() => {
            anyhow::anyhow!("server error from {url} ({status})")
        }
        _ => anyhow::anyhow!("request failed for {url} ({status})"),
    }
}

#[allow(dead_code)]
pub(crate) async fn send_get_with_retry(
    client: &Client,
    url: &str,
    bearer: Option<&HeaderValue>,
) -> anyhow::Result<String> {
    let mut attempt = 0;

    loop {
        let mut request = client.get(url);

        if let Some(value) = bearer {
            request = request.header(AUTHORIZATION, value);
        }

        let response = request
            .send()
            .await
            .map_err(|error| anyhow::anyhow!("failed to send request to {url}: {error}"))?;

        let status = response.status();

        if status.is_success() {
            return response.text().await.map_err(|error| {
                anyhow::anyhow!("failed to read response body from {url}: {error}")
            });
        }

        if let Some(delay) = retry_delay_for(status, response.headers(), attempt) {
            attempt += 1;
            tokio::time::sleep(delay).await;
            continue;
        }

        return Err(map_status_error(status, url));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn build_bearer_header_adds_scheme() {
        let value = build_bearer_header("token-123").unwrap();

        assert_eq!(value.to_str().unwrap(), "Bearer token-123");
    }

    #[test]
    fn retry_delay_for_uses_retry_after_on_429() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));

        let delay = retry_delay_for(StatusCode::TOO_MANY_REQUESTS, &headers, 0).unwrap();

        assert_eq!(delay, Duration::from_secs(7));
    }

    #[tokio::test]
    async fn send_get_with_retry_sends_bearer_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut buffer = [0_u8; 2048];
            let bytes_read = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();

            request
        });

        let client = build_http_client(Duration::from_secs(2), "daemon-test/1.0").unwrap();
        let bearer = build_bearer_header("secret-token").unwrap();
        let response = send_get_with_retry(&client, &format!("http://{addr}"), Some(&bearer))
            .await
            .unwrap();

        let request = server.await.unwrap();
        let request_lower = request.to_ascii_lowercase();

        assert_eq!(response, "ok");
        assert!(request_lower.contains("authorization: bearer secret-token"));
        assert!(request_lower.contains("user-agent: daemon-test/1.0"));
    }

    #[test]
    fn map_status_error_returns_authentication_failed_for_401() {
        let error = map_status_error(StatusCode::UNAUTHORIZED, "http://example.com");
        assert!(error.to_string().contains("authentication failed"));
        assert!(error.to_string().contains("401"));
    }

    #[test]
    fn map_status_error_returns_permission_denied_for_403() {
        let error = map_status_error(StatusCode::FORBIDDEN, "http://example.com");
        assert!(error.to_string().contains("permission denied"));
        assert!(error.to_string().contains("403"));
    }

    #[test]
    fn map_status_error_returns_not_found_for_404() {
        let error = map_status_error(StatusCode::NOT_FOUND, "http://example.com");
        assert!(error.to_string().contains("not found"));
        assert!(error.to_string().contains("404"));
    }

    #[test]
    fn map_status_error_returns_rate_limited_for_429() {
        let error = map_status_error(StatusCode::TOO_MANY_REQUESTS, "http://example.com");
        assert!(error.to_string().contains("rate limited"));
        assert!(error.to_string().contains("429"));
    }

    #[test]
    fn map_status_error_returns_server_error_for_500() {
        let error = map_status_error(StatusCode::INTERNAL_SERVER_ERROR, "http://example.com");
        assert!(error.to_string().contains("server error"));
    }

    #[test]
    fn map_status_error_returns_generic_for_other_status() {
        let error = map_status_error(StatusCode::BAD_REQUEST, "http://example.com");
        assert!(error.to_string().contains("request failed"));
        assert!(error.to_string().contains("400"));
    }

    #[test]
    fn retry_delay_for_returns_exponential_backoff_for_5xx() {
        let headers = HeaderMap::new();

        let delay_0 = retry_delay_for(StatusCode::INTERNAL_SERVER_ERROR, &headers, 0).unwrap();
        assert_eq!(delay_0, Duration::from_secs(1));

        let delay_1 = retry_delay_for(StatusCode::INTERNAL_SERVER_ERROR, &headers, 1).unwrap();
        assert_eq!(delay_1, Duration::from_secs(2));

        let delay_2 = retry_delay_for(StatusCode::INTERNAL_SERVER_ERROR, &headers, 2).unwrap();
        assert_eq!(delay_2, Duration::from_secs(4));
    }

    #[test]
    fn retry_delay_for_returns_none_when_max_retries_exceeded() {
        let headers = HeaderMap::new();
        let delay = retry_delay_for(
            StatusCode::INTERNAL_SERVER_ERROR,
            &headers,
            MAX_HTTP_RETRIES,
        );
        assert!(delay.is_none());
    }

    #[test]
    fn retry_delay_for_returns_none_for_client_error() {
        let headers = HeaderMap::new();
        let delay = retry_delay_for(StatusCode::BAD_REQUEST, &headers, 0);
        assert!(delay.is_none());
    }

    #[test]
    fn retry_delay_for_429_uses_fallback_when_no_retry_after() {
        let headers = HeaderMap::new();
        let delay = retry_delay_for(StatusCode::TOO_MANY_REQUESTS, &headers, 0).unwrap();
        assert_eq!(delay, Duration::from_secs(1));
    }
}
