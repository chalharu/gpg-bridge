use super::*;

#[test]
fn display_qr_produces_qr_output() {
    let mut buf = Vec::new();
    display_qr(&mut buf, "test-token-123", 120).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Pairing QR Code"));
    // QR output should contain block characters or spaces
    assert!(output.contains(' '));
}

#[test]
fn display_qr_handles_long_input() {
    let mut buf = Vec::new();
    display_qr(&mut buf, &"a".repeat(500), 60).unwrap();
}

#[tokio::test]
async fn fetch_pairing_token_handles_connection_error() {
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, "http://127.0.0.1:1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn fetch_pairing_token_parses_response() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let body = r#"{"pairing_token":"tok-abc","expires_in":300}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.pairing_token, "tok-abc");
    assert_eq!(resp.expires_in, 300);
}

#[tokio::test]
async fn fetch_pairing_token_returns_error_on_non_success() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let response = "HTTP/1.1 500 Internal Server Error\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = fetch_pairing_token(&client, &format!("http://{addr}")).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("500"));
}

#[tokio::test]
async fn wait_for_paired_event_extracts_token() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let sse_body = concat!(
            "event: heartbeat\ndata: \n\n",
            "event: paired\n",
            "data: {\"client_jwt\":\"jwt-xyz\",\"client_id\":\"cid-123\"}\n\n",
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Connection: close\r\n\r\n\
             {sse_body}"
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
        .await
        .unwrap();
    assert_eq!(entry.client_jwt, "jwt-xyz");
    assert_eq!(entry.client_id, "cid-123");
}

#[tokio::test]
async fn wait_for_paired_event_aborts_on_401() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let response = "HTTP/1.1 401 Unauthorized\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let result = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("401"));
}

#[tokio::test]
async fn wait_for_paired_event_retries_on_503_then_succeeds() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // First connection: transient 503
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let response = "HTTP/1.1 503 Service Unavailable\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
        drop(socket);

        // Second connection: success
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let sse_body = "event: paired\n\
                        data: {\"client_jwt\":\"jwt-r\",\"client_id\":\"cid-r\"}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Connection: close\r\n\r\n\
             {sse_body}"
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let entry = wait_for_paired_event(&client, &format!("http://{addr}"), "pairing-jwt")
        .await
        .unwrap();
    assert_eq!(entry.client_jwt, "jwt-r");
    assert_eq!(entry.client_id, "cid-r");
}

#[test]
fn display_pairing_complete_writes_warning() {
    let mut buf = Vec::new();
    display_pairing_complete(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Pairing Complete"));
    assert!(output.contains("did not initiate this pairing"));
    assert!(output.contains("unpair"));
}

#[tokio::test]
async fn run_pairing_flow_end_to_end() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // First connection: pairing-token
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let body = r#"{"pairing_token":"pt-1","expires_in":60}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        drop(socket);

        // Second connection: pairing-session SSE
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let sse_body =
            "event: paired\ndata: {\"client_jwt\":\"jwt-1\",\"client_id\":\"cid-1\"}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Connection: close\r\n\r\n\
             {sse_body}"
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("tokens.json");
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let mut output = Vec::new();
    run_pairing_flow(&client, &format!("http://{addr}"), &token_path, &mut output)
        .await
        .unwrap();

    let entries = crate::token_store::load_tokens(&token_path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client_id, "cid-1");
    assert_eq!(entries[0].client_jwt, "jwt-1");

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Pairing QR Code"));
    assert!(output_str.contains("Pairing Complete"));
}
