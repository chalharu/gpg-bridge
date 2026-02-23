use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eventsource_stream::{Event, Eventsource};
use futures_util::StreamExt;
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, HeaderMap, HeaderValue, RETRY_AFTER},
};
use thiserror::Error;
use tokio::sync::watch;

const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct SseClientConfig {
    pub url: String,
    pub heartbeat_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl SseClientConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }

    #[cfg(test)]
    pub fn with_heartbeat_timeout(mut self, timeout: Duration) -> Self {
        self.heartbeat_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub fn with_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.initial_backoff = initial;
        self.max_backoff = max;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSseEvent {
    Heartbeat,
    Message {
        event_type: String,
        data: String,
        id: Option<String>,
    },
}

#[derive(Debug, Error)]
pub enum SseClientError {
    #[error("sse client url must not be empty")]
    EmptyUrl,
    #[error("failed to connect sse endpoint {url}: {source}")]
    Connect {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("sse endpoint returned non-success status {status} for {url}")]
    ConnectStatus {
        url: String,
        status: StatusCode,
        retry_after: Option<Duration>,
    },
    #[error("heartbeat timeout ({timeout_secs}s) while reading sse stream")]
    HeartbeatTimeout { timeout_secs: u64 },
    #[error("sse stream ended")]
    StreamEnded,
    #[error("sse stream error: {0}")]
    Stream(String),
    #[error("event handler failed: {0}")]
    Handler(#[source] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct SseClient {
    client: Client,
    config: SseClientConfig,
}

impl SseClient {
    pub fn new(client: Client, config: SseClientConfig) -> Result<Self, SseClientError> {
        if config.url.trim().is_empty() {
            return Err(SseClientError::EmptyUrl);
        }

        Ok(Self { client, config })
    }

    #[cfg(test)]
    pub async fn receive_single_event(&self) -> Result<DaemonSseEvent, SseClientError> {
        let response = self.connect(None).await?;
        let mut stream = response.bytes_stream().eventsource();

        let next = tokio::time::timeout(self.config.heartbeat_timeout, stream.next())
            .await
            .map_err(|_| SseClientError::HeartbeatTimeout {
                timeout_secs: self.config.heartbeat_timeout.as_secs(),
            })?;

        match next {
            Some(Ok(event)) => Ok(dispatch_event(&event)),
            Some(Err(error)) => Err(SseClientError::Stream(error.to_string())),
            None => Err(SseClientError::StreamEnded),
        }
    }

    pub async fn run_with_handler<F, Fut>(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
        mut handler: F,
    ) -> Result<(), SseClientError>
    where
        F: FnMut(DaemonSseEvent) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let mut attempt: u32 = 0;
        let mut last_event_id: Option<String> = None;

        loop {
            let response = match self.connect(last_event_id.as_deref()).await {
                Ok(response) => response,
                Err(error) => {
                    let delay = reconnect_delay_for_error(
                        &self.config,
                        &error,
                        attempt,
                        random_jitter_seed(),
                    );
                    tracing::warn!(?error, attempt, ?delay, "sse connect failed; retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {},
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                return Ok(());
                            }
                        }
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };

            attempt = 0;
            let mut stream = response.bytes_stream().eventsource();

            loop {
                let next = tokio::select! {
                    result = tokio::time::timeout(self.config.heartbeat_timeout, stream.next()) => result,
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        continue;
                    }
                };

                match next {
                    Ok(Some(Ok(event))) => {
                        let dispatched = dispatch_event(&event);
                        if let DaemonSseEvent::Message {
                            id: Some(ref id), ..
                        } = dispatched
                        {
                            last_event_id = Some(id.clone());
                        }
                        handler(dispatched).await.map_err(SseClientError::Handler)?;
                    }
                    Ok(Some(Err(error))) => {
                        let error = SseClientError::Stream(error.to_string());
                        let delay = reconnect_delay_for_error(
                            &self.config,
                            &error,
                            attempt,
                            random_jitter_seed(),
                        );
                        tracing::warn!(
                            ?error,
                            attempt,
                            ?delay,
                            "sse stream read failed; reconnecting"
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {},
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    return Ok(());
                                }
                            }
                        }
                        attempt = attempt.saturating_add(1);
                        break;
                    }
                    Ok(None) => {
                        let error = SseClientError::StreamEnded;
                        let delay = reconnect_delay_for_error(
                            &self.config,
                            &error,
                            attempt,
                            random_jitter_seed(),
                        );
                        tracing::warn!(attempt, ?delay, "sse stream ended; reconnecting");
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {},
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    return Ok(());
                                }
                            }
                        }
                        attempt = attempt.saturating_add(1);
                        break;
                    }
                    Err(_) => {
                        let error = SseClientError::HeartbeatTimeout {
                            timeout_secs: self.config.heartbeat_timeout.as_secs(),
                        };
                        let delay = reconnect_delay_for_error(
                            &self.config,
                            &error,
                            attempt,
                            random_jitter_seed(),
                        );
                        tracing::warn!(attempt, ?delay, "heartbeat timeout; reconnecting");
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {},
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    return Ok(());
                                }
                            }
                        }
                        attempt = attempt.saturating_add(1);
                        break;
                    }
                }
            }
        }
    }

    async fn connect(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<reqwest::Response, SseClientError> {
        let mut request = self
            .client
            .get(&self.config.url)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"));

        if let Some(id) = last_event_id {
            request = request.header("Last-Event-ID", id);
        }

        let response = request
            .send()
            .await
            .map_err(|source| SseClientError::Connect {
                url: self.config.url.clone(),
                source,
            })?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let retry_after = if status == StatusCode::TOO_MANY_REQUESTS {
            parse_retry_after(response.headers())
        } else {
            None
        };

        Err(SseClientError::ConnectStatus {
            url: self.config.url.clone(),
            status,
            retry_after,
        })
    }
}

pub(crate) fn dispatch_event(event: &Event) -> DaemonSseEvent {
    if event.event == "heartbeat" {
        return DaemonSseEvent::Heartbeat;
    }

    DaemonSseEvent::Message {
        event_type: event.event.clone(),
        data: event.data.clone(),
        id: if event.id.is_empty() {
            None
        } else {
            Some(event.id.clone())
        },
    }
}

fn reconnect_delay_for_error(
    config: &SseClientConfig,
    error: &SseClientError,
    attempt: u32,
    jitter_seed: u64,
) -> Duration {
    let backoff = exponential_backoff_with_jitter(config, attempt, jitter_seed);

    match error {
        SseClientError::ConnectStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after,
            ..
        } => {
            if let Some(retry_after) = retry_after {
                return std::cmp::max(backoff, *retry_after);
            }
            backoff
        }
        _ => backoff,
    }
}

fn exponential_backoff_with_jitter(
    config: &SseClientConfig,
    attempt: u32,
    jitter_seed: u64,
) -> Duration {
    let exponent = attempt.min(16);
    let base = config
        .initial_backoff
        .saturating_mul(2_u32.saturating_pow(exponent))
        .min(config.max_backoff);

    let jitter_bound_millis = (base.as_millis() / 4).max(1) as u64;
    let jitter_millis = jitter_seed % (jitter_bound_millis + 1);
    base.saturating_add(Duration::from_millis(jitter_millis))
        .min(config.max_backoff)
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn random_jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn dispatches_heartbeat_event() {
        let event = Event {
            event: "heartbeat".to_owned(),
            data: "".to_owned(),
            id: "".to_owned(),
            retry: None,
        };

        let dispatched = dispatch_event(&event);
        assert_eq!(dispatched, DaemonSseEvent::Heartbeat);
    }

    #[test]
    fn delay_for_429_uses_max_of_retry_after_and_backoff() {
        let config = SseClientConfig::new("http://localhost/sse")
            .with_backoff(Duration::from_secs(1), Duration::from_secs(30));
        let error = SseClientError::ConnectStatus {
            url: "http://localhost/sse".to_owned(),
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: Some(Duration::from_secs(10)),
        };

        let delay = reconnect_delay_for_error(&config, &error, 0, 0);
        assert_eq!(delay, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn receives_sse_event_from_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream\r\n",
                "Cache-Control: no-cache\r\n",
                "Connection: close\r\n\r\n",
                "event: signed\n",
                "id: 42\n",
                "data: payload\n\n"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let config = SseClientConfig::new(format!("http://{addr}"))
            .with_heartbeat_timeout(Duration::from_secs(2));
        let sse_client = SseClient::new(client, config).unwrap();

        let event = sse_client.receive_single_event().await.unwrap();
        assert_eq!(
            event,
            DaemonSseEvent::Message {
                event_type: "signed".to_owned(),
                data: "payload".to_owned(),
                id: Some("42".to_owned()),
            }
        );
    }

    #[tokio::test]
    async fn heartbeat_timeout_is_detected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream\r\n",
                "Cache-Control: no-cache\r\n",
                "Connection: keep-alive\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let config = SseClientConfig::new(format!("http://{addr}"))
            .with_heartbeat_timeout(Duration::from_millis(100));
        let sse_client = SseClient::new(client, config).unwrap();

        let error = sse_client.receive_single_event().await.unwrap_err();
        assert!(matches!(error, SseClientError::HeartbeatTimeout { .. }));
    }
}
