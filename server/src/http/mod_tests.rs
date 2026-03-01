use super::*;
use axum::{
    body::{self, Body},
    http::{Request, StatusCode, header::HeaderName},
    response::IntoResponse,
};
use tower::ServiceExt;

use super::accept::ACCEPT_VERSION_V1;
use crate::test_support::MockRepository;
use crate::{config::AppConfig, repository::build_repository};

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

#[tokio::test]
async fn health_returns_ok_status() {
    let config = AppConfig {
        server_host: "127.0.0.1".to_owned(),
        server_port: 3000,
        database_url: "sqlite::memory:".to_owned(),
        db_max_connections: 4,
        db_min_connections: 1,
        db_acquire_timeout_seconds: 5,
        log_level: "info".to_owned(),
        log_format: "plain".to_owned(),
        signing_key_secret: "test-secret-key!".to_owned(),
        base_url: "http://localhost:3000".to_owned(),
        rate_limit_strict_quota: 10,
        rate_limit_strict_window_seconds: 60,
        rate_limit_standard_quota: 60,
        rate_limit_standard_window_seconds: 60,
        rate_limit_sse_max_per_ip: 20,
        rate_limit_sse_max_per_key: 1,
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_service_account_key_path: None,
        fcm_project_id: None,
        cleanup_interval_seconds: 60,
        unpaired_client_max_age_hours: 24,
        audit_log_approved_retention_seconds: 31_536_000,
        audit_log_denied_retention_seconds: 15_768_000,
        audit_log_conflict_retention_seconds: 7_884_000,
    };

    let repository = build_repository(&config).await.unwrap();
    repository.run_migrations().await.unwrap();

    let state = AppState {
        repository,
        base_url: "http://localhost:3000".to_owned(),
        signing_key_secret: "test-secret-key!".to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_validator: Arc::new(fcm::NoopFcmValidator),
        fcm_sender: Arc::new(fcm::NoopFcmSender),
        sse_tracker: SseConnectionTracker::new(rate_limit::config::SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: SignEventNotifier::new(),
    };
    let Json(response) = health(axum::extract::State(state)).await.unwrap();

    assert_eq!(response.status, "ok");
}

#[tokio::test]
async fn health_returns_problem_details_when_repository_unavailable() {
    let state = AppState {
        repository: Arc::new(failing_mock()),
        base_url: "http://localhost:3000".to_owned(),
        signing_key_secret: "test-secret-key!".to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_validator: Arc::new(fcm::NoopFcmValidator),
        fcm_sender: Arc::new(fcm::NoopFcmSender),
        sse_tracker: SseConnectionTracker::new(rate_limit::config::SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: SignEventNotifier::new(),
    };

    let error = health(axum::extract::State(state)).await.unwrap_err();
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

fn test_state(repo: impl SignatureRepository + 'static) -> AppState {
    AppState {
        repository: Arc::new(repo),
        base_url: "http://localhost:3000".to_owned(),
        signing_key_secret: "test-secret-key!".to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        pairing_jwt_validity_seconds: 300,
        client_jwt_validity_seconds: 31_536_000,
        request_jwt_validity_seconds: 300,
        unconsumed_pairing_limit: 100,
        fcm_validator: Arc::new(fcm::NoopFcmValidator),
        fcm_sender: Arc::new(fcm::NoopFcmSender),
        sse_tracker: SseConnectionTracker::new(rate_limit::config::SseConnectionConfig {
            max_per_ip: 20,
            max_per_key: 1,
        }),
        pairing_notifier: PairingNotifier::new(),
        sign_event_notifier: SignEventNotifier::new(),
    }
}

#[tokio::test]
async fn router_rejects_unsupported_accept_with_406() {
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/vnd.gpg-bridge.v2+json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

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
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, ACCEPT_VERSION_V1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

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
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_accepts_mixed_case_media_type() {
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "Application/Vnd.Gpg-Sign.V1+Json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_rejects_accept_media_type_with_zero_quality() {
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/json;q=0, text/plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn router_accepts_application_wildcard() {
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/*")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        ACCEPT_VERSION_V1
    );
}

#[tokio::test]
async fn router_handles_cors_preflight_options() {
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

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
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

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
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

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
    let app = build_router(test_state(healthy_mock()), test_rate_limit_config());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::ACCEPT, "application/json;Q=0.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

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

    let app = build_router(test_state(healthy_mock()), rl_config);

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
