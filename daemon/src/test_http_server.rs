use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub(crate) async fn spawn_single_response_server(response: impl Into<String>) -> SocketAddr {
    let response = response.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer).await;
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    addr
}

pub(crate) async fn spawn_single_response_server_with_request(
    response: impl Into<String>,
) -> (SocketAddr, JoinHandle<String>) {
    let response = response.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let bytes_read = socket.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

        socket.write_all(response.as_bytes()).await.unwrap();

        request
    });

    (addr, server)
}

pub(crate) async fn spawn_response_sequence(responses: Vec<String>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        for response in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });

    addr
}

pub(crate) fn empty_response(status_line: &str) -> String {
    format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

pub(crate) fn text_response(status_line: &str, body: &str) -> String {
    format!(
        "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

pub(crate) fn json_response(status_line: &str, body: &str) -> String {
    format!(
        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

pub(crate) fn sse_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}"
    )
}