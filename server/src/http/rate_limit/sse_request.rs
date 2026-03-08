use std::net::IpAddr;

use axum::extract::{ConnectInfo, Request};

use crate::error::AppError;
use crate::http::AppState;

use super::ip_extractor::extract_client_ip;
use super::sse_tracker::{SseConnectionGuard, SseRejection};

pub(crate) fn resolve_client_ip(request: &Request, instance: &str) -> Result<IpAddr, AppError> {
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .cloned();

    extract_client_ip(request.headers(), connect_info.as_ref())
        .ok_or_else(|| AppError::internal("could not determine client IP").with_instance(instance))
}

pub(crate) fn acquire_sse_slot(
    state: &AppState,
    ip: IpAddr,
    key: &str,
    key_limit_message: &str,
    instance: &str,
) -> Result<SseConnectionGuard, AppError> {
    state
        .sse_tracker
        .try_acquire(ip, key.to_owned())
        .map_err(|rejection| match rejection {
            SseRejection::IpLimitExceeded { .. } => {
                AppError::too_many_requests("SSE connection limit per IP exceeded")
                    .with_instance(instance)
            }
            SseRejection::KeyLimitExceeded { .. } => {
                AppError::too_many_requests(key_limit_message).with_instance(instance)
            }
        })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::response::IntoResponse;

    use crate::test_support::{
        MockRepository, make_signing_key_row, make_test_app_state, response_json,
    };

    use super::*;

    fn make_state() -> AppState {
        let (private_jwk, public_jwk, kid) = crate::jwt::generate_signing_key_pair().unwrap();
        let signing_key = make_signing_key_row(&private_jwk, &public_jwk, &kid);
        make_test_app_state(MockRepository::new(signing_key))
    }

    #[test]
    fn resolve_client_ip_prefers_forwarded_header() {
        let request = Request::builder()
            .header("X-Forwarded-For", "203.0.113.10, 10.0.0.1")
            .body(Body::empty())
            .unwrap();

        let ip = resolve_client_ip(&request, "/test").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    }

    #[test]
    fn resolve_client_ip_uses_connect_info_fallback() {
        let mut request = Request::builder().body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                Ipv4Addr::new(127, 0, 0, 1),
                8080,
            ))));

        let ip = resolve_client_ip(&request, "/test").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn resolve_client_ip_reports_instance_when_unavailable() {
        let request = Request::builder().body(Body::empty()).unwrap();

        let error = match resolve_client_ip(&request, "/sign-events") {
            Ok(_) => panic!("expected client IP resolution to fail"),
            Err(error) => error,
        };
        let response = error.into_response();
        let body = response_json(response).await;

        assert_eq!(body["detail"], "could not determine client IP");
        assert_eq!(body["instance"], "/sign-events");
    }

    #[tokio::test]
    async fn acquire_sse_slot_uses_custom_key_limit_message() {
        let state = make_state();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let _guard =
            acquire_sse_slot(&state, ip, "pair-1", "custom key limit", "/pairing").unwrap();

        let error = match acquire_sse_slot(&state, ip, "pair-1", "custom key limit", "/pairing") {
            Ok(_) => panic!("expected SSE slot acquisition to fail"),
            Err(error) => error,
        };
        let response = error.into_response();
        let body = response_json(response).await;

        assert_eq!(body["detail"], "custom key limit");
        assert_eq!(body["instance"], "/pairing");
    }

    #[tokio::test]
    async fn acquire_sse_slot_reports_ip_limit_with_instance() {
        let state = make_state();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut guards = Vec::new();
        for idx in 0..20 {
            guards.push(
                acquire_sse_slot(
                    &state,
                    ip,
                    &format!("pair-{idx}"),
                    "custom key limit",
                    "/sign-events",
                )
                .unwrap(),
            );
        }

        let error = match acquire_sse_slot(
            &state,
            ip,
            "pair-overflow",
            "custom key limit",
            "/sign-events",
        ) {
            Ok(_) => panic!("expected IP SSE slot acquisition to fail"),
            Err(error) => error,
        };
        let response = error.into_response();
        let body = response_json(response).await;

        assert_eq!(body["detail"], "SSE connection limit per IP exceeded");
        assert_eq!(body["instance"], "/sign-events");

        drop(guards);
    }
}
