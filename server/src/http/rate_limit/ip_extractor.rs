use std::net::IpAddr;

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

/// Header name for forwarded client IP (set by reverse proxies like Fly.io).
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Extract the client IP address from the request.
///
/// Uses the leftmost IP from `X-Forwarded-For` if present,
/// otherwise falls back to the peer socket address.
pub fn extract_client_ip(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<std::net::SocketAddr>>,
) -> Option<IpAddr> {
    if let Some(ip) = extract_from_forwarded_for(headers) {
        return Some(ip);
    }
    connect_info.map(|ci| ci.0.ip())
}

/// Parse the leftmost IP from the `X-Forwarded-For` header.
fn extract_from_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let header_value = headers.get(X_FORWARDED_FOR)?;
    let header_str = header_value.to_str().ok()?;

    header_str
        .split(',')
        .next()
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use axum::http::HeaderValue;

    use super::*;

    fn make_headers(xff: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_str(xff).unwrap());
        headers
    }

    #[test]
    fn extracts_single_ipv4_from_xff() {
        let headers = make_headers("203.0.113.50");
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
    }

    #[test]
    fn extracts_leftmost_ip_from_xff_chain() {
        let headers = make_headers("203.0.113.50, 70.41.3.18, 150.172.238.178");
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
    }

    #[test]
    fn extracts_ipv6_from_xff() {
        let headers = make_headers("2001:db8::1");
        let ip = extract_client_ip(&headers, None);
        assert_eq!(
            ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn falls_back_to_connect_info() {
        let headers = HeaderMap::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let ci = ConnectInfo(addr);
        let ip = extract_client_ip(&headers, Some(&ci));
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn returns_none_without_xff_or_connect_info() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, None);
    }

    #[test]
    fn ignores_invalid_xff_value() {
        let headers = make_headers("not-an-ip");
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, None);
    }

    #[test]
    fn handles_xff_with_whitespace() {
        let headers = make_headers("  203.0.113.50  , 10.0.0.1");
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
    }

    #[test]
    fn xff_takes_precedence_over_connect_info() {
        let headers = make_headers("203.0.113.50");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);
        let ci = ConnectInfo(addr);
        let ip = extract_client_ip(&headers, Some(&ci));
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
    }
}
