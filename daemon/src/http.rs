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

pub(crate) async fn send_post_json_with_retry(
    client: &Client,
    url: &str,
    bearer: Option<&HeaderValue>,
    body: &serde_json::Value,
) -> anyhow::Result<String> {
    let mut attempt = 0;

    loop {
        let mut request = client.post(url).json(body);

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

/// Send a PATCH request with JSON body, retrying on 5xx/429.
///
/// Returns the HTTP status code on success (2xx) or 409 Conflict.
pub(crate) async fn send_patch_json_with_retry(
    client: &Client,
    url: &str,
    bearer: Option<&HeaderValue>,
    body: &serde_json::Value,
) -> anyhow::Result<u16> {
    let mut attempt = 0;

    loop {
        let mut request = client.patch(url).json(body);

        if let Some(value) = bearer {
            request = request.header(AUTHORIZATION, value);
        }

        let response = request
            .send()
            .await
            .map_err(|error| anyhow::anyhow!("failed to send PATCH to {url}: {error}"))?;

        let status = response.status();

        if status.is_success() || status == StatusCode::CONFLICT {
            return Ok(status.as_u16());
        }

        if let Some(delay) = retry_delay_for(status, response.headers(), attempt) {
            attempt += 1;
            tokio::time::sleep(delay).await;
            continue;
        }

        return Err(map_status_error(status, url));
    }
}

/// Send a DELETE request, retrying on 5xx/429.
///
/// Returns the HTTP status code on success (2xx), 409 Conflict, or 404 Not Found.
pub(crate) async fn send_delete_with_retry(
    client: &Client,
    url: &str,
    bearer: Option<&HeaderValue>,
) -> anyhow::Result<u16> {
    let mut attempt = 0;

    loop {
        let mut request = client.delete(url);

        if let Some(value) = bearer {
            request = request.header(AUTHORIZATION, value);
        }

        let response = request
            .send()
            .await
            .map_err(|error| anyhow::anyhow!("failed to send DELETE to {url}: {error}"))?;

        let status = response.status();

        if status.is_success() || status == StatusCode::CONFLICT || status == StatusCode::NOT_FOUND
        {
            return Ok(status.as_u16());
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
#[path = "test_http_server.rs"]
mod test_http_server;

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
