use super::*;
use axum::{
    Router,
    body::{self, Body},
    http::{Request, StatusCode, header::HeaderName},
    response::IntoResponse,
};
use tower::ServiceExt;

use super::accept::ACCEPT_VERSION_V1;
use crate::config::AppConfig;
use crate::repository::build_repository;
use crate::test_support::{MockRepository, make_test_app_state, make_test_app_state_arc};

use super::rate_limit::config::{SseConnectionConfig, TierConfig};

fn test_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        strict: TierConfig {
            quota: 1000,
            window_seconds: 60,
        },
        standard: TierConfig {
            quota: 1000,
            window_seconds: 60,
        },
        sse: SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        },
    }
}

fn test_app_config() -> AppConfig {
    AppConfig::from_lookup(&|key| match key {
        "SERVER_DATABASE_URL" => Some("sqlite::memory:".to_owned()),
        "SERVER_SIGNING_KEY_SECRET" => Some("test-secret-key!".to_owned()),
        "SERVER_BASE_URL" => Some("http://localhost:3000".to_owned()),
        _ => None,
    })
    .unwrap()
}

#[tokio::test]
async fn health_returns_ok_status() {
    let config = test_app_config();

    let repository = build_repository(&config).await.unwrap();
    repository.run_migrations().await.unwrap();

    let Json(response) = health(axum::extract::State(make_test_app_state_arc(repository)))
        .await
        .unwrap();

    assert_eq!(response.status, "ok");
}

#[tokio::test]
async fn health_returns_problem_details_when_repository_unavailable() {
    let error = health(axum::extract::State(make_test_app_state(failing_mock())))
        .await
        .unwrap_err();
    let response = error.into_response();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "application/problem+json"
    );

    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_text.contains("\"type\""));
    assert!(body_text.contains("\"title\""));
    assert!(body_text.contains("\"status\""));
    assert!(body_text.contains("\"detail\""));
    assert!(body_text.contains("\"instance\""));
}

fn healthy_mock() -> MockRepository {
    MockRepository {
        backend: "sqlite",
        ..Default::default()
    }
}

fn failing_mock() -> MockRepository {
    MockRepository {
        fail_health: true,
        backend: "sqlite",
        ..Default::default()
    }
}

fn test_app() -> Router {
    build_router(
        make_test_app_state(healthy_mock()),
        test_rate_limit_config(),
    )
}

async fn get_health_response(app: Router, accept_header: &str) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::GET)
            .uri("/health")
            .header(header::ACCEPT, accept_header)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn router_rejects_unsupported_accept_with_406() {
    let response = get_health_response(test_app(), "application/vnd.gpg-bridge.v2+json").await;

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        response
            .headers()
            .get(HeaderName::from_static("x-content-type-options"))
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_text.contains("\"type\""));
    assert!(body_text.contains("\"title\""));
    assert!(body_text.contains("\"status\":406"));
    assert!(body_text.contains("\"detail\""));
    assert!(body_text.contains("\"instance\""));
}

#[tokio::test]
async fn router_accepts_v1_media_type_and_adds_security_headers() {
    let response = get_health_response(test_app(), ACCEPT_VERSION_V1).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
    assert!(
        response
            .headers()
            .get(header::VARY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Accept")
    );
    assert_eq!(
        response
            .headers()
            .get(HeaderName::from_static("x-content-type-options"))
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn router_accepts_application_json_and_returns_versioned_content_type() {
    let response = get_health_response(test_app(), "application/json").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_accepts_mixed_case_media_type() {
    let response = get_health_response(test_app(), "Application/Vnd.Gpg-Sign.V1+Json").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_rejects_accept_media_type_with_zero_quality() {
    let response = get_health_response(test_app(), "application/json;q=0, text/plain").await;

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn router_accepts_application_wildcard() {
    let response = get_health_response(test_app(), "application/*").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_handles_cors_preflight_options() {
    let app = build_router(
        make_test_app_state(healthy_mock()),
        test_rate_limit_config(),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/health")
                .header(header::ORIGIN, "https://example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "*"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("GET")
    );
}

#[tokio::test]
async fn router_cors_preflight_allows_authorization_header() {
    let app = build_router(
        make_test_app_state(healthy_mock()),
        test_rate_limit_config(),
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/health")
                .header(header::ORIGIN, "https://example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT);

    let allow_headers = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allow_headers.contains("authorization"));
    assert!(allow_headers.contains("content-type"));
}

#[tokio::test]
async fn router_cors_preflight_allows_patch_and_delete_methods() {
    let app = build_router(
        make_test_app_state(healthy_mock()),
        test_rate_limit_config(),
    );

    for request_method in [Method::PATCH, Method::DELETE] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/health")
                    .header(header::ORIGIN, "https://example.com")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_METHOD,
                        request_method.as_str(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT);

        let allow_methods = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(allow_methods.contains("PATCH"));
        assert!(allow_methods.contains("DELETE"));
    }
}

#[tokio::test]
async fn router_accepts_uppercase_q_parameter_name() {
    let response = get_health_response(test_app(), "application/json;Q=0.8").await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn router_returns_429_when_rate_limit_exceeded() {
    let rl_config = RateLimitConfig {
        strict: TierConfig {
            quota: 1000,
            window_seconds: 60,
        },
        standard: TierConfig {
            quota: 2,
            window_seconds: 60,
        },
        sse: SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        },
    };

    let app = build_router(make_test_app_state(healthy_mock()), rl_config);

    // Exhaust the standard quota (2 requests).
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::ACCEPT, "application/json")
                    .header("x-forwarded-for", "10.0.0.99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Third request should be rejected with 429.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/json")
                .header("x-forwarded-for", "10.0.0.99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert!(response.headers().get(header::RETRY_AFTER).is_some());
    assert!(
        response
            .headers()
            .get(HeaderName::from_static("ratelimit-policy"))
            .is_some()
    );
    assert!(
        response
            .headers()
            .get(HeaderName::from_static("ratelimit"))
            .is_some()
    );

    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_text.contains("\"status\":429"));
    assert!(body_text.contains("rate-limit"));
}
