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

#[test]
fn exponential_backoff_with_jitter_computes_correct_value() {
    let config = SseClientConfig::new("http://localhost/sse")
        .with_backoff(Duration::from_secs(1), Duration::from_secs(30));

    // base=1000ms, jitter_bound=250, jitter=500%251=249, result=1249ms
    let delay = exponential_backoff_with_jitter(&config, 0, 500);
    assert_eq!(delay, Duration::from_millis(1249));
}

#[test]
fn exponential_backoff_with_jitter_increases_with_attempt() {
    let config = SseClientConfig::new("http://localhost/sse")
        .with_backoff(Duration::from_secs(1), Duration::from_secs(30));

    let d0 = exponential_backoff_with_jitter(&config, 0, 0);
    let d1 = exponential_backoff_with_jitter(&config, 1, 0);
    let d2 = exponential_backoff_with_jitter(&config, 2, 0);

    assert_eq!(d0, Duration::from_secs(1));
    assert_eq!(d1, Duration::from_secs(2));
    assert_eq!(d2, Duration::from_secs(4));
}

#[test]
fn exponential_backoff_jitter_bounded_to_quarter_of_base() {
    let config = SseClientConfig::new("http://localhost/sse")
        .with_backoff(Duration::from_secs(1), Duration::from_secs(30));

    let delay = exponential_backoff_with_jitter(&config, 0, u64::MAX);
    assert!(delay >= Duration::from_secs(1));
    assert!(delay <= Duration::from_millis(1250));
}

#[test]
fn parse_retry_after_returns_duration_from_header() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
    let result = parse_retry_after(&headers);
    assert_eq!(result, Some(Duration::from_secs(5)));
}

#[test]
fn parse_retry_after_returns_none_when_absent() {
    let headers = HeaderMap::new();
    assert!(parse_retry_after(&headers).is_none());
}

#[test]
fn parse_retry_after_returns_none_for_non_numeric() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("invalid"));
    assert!(parse_retry_after(&headers).is_none());
}

#[test]
fn exponential_backoff_with_jitter_caps_at_max_backoff() {
    let config = SseClientConfig::new("http://localhost/sse")
        .with_backoff(Duration::from_secs(1), Duration::from_secs(30));

    // attempt=10 → base = 1024s capped to 30s, jitter also capped
    let delay = exponential_backoff_with_jitter(&config, 10, 0);
    assert_eq!(delay, Duration::from_secs(30));
}

#[test]
fn random_jitter_seed_returns_nonzero_value() {
    // NOTE: limited coverage due to non-deterministic output;
    // this test kills the → 0 and → 1 replacement mutations.
    let seed = random_jitter_seed();
    assert!(seed > 1);
}
