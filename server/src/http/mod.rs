mod accept;
pub mod auth;
mod device;
pub mod fcm;
mod middleware;
pub mod pairing;
pub mod rate_limit;
pub mod signing;

use std::sync::Arc;

use axum::{
    Json, Router,
    http::{
        Method,
        header::{self},
    },
    routing::{delete, get, patch, post},
};
use serde::Serialize;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::Level;

use crate::error::AppError;
use crate::repository::SignatureRepository;

use self::fcm::FcmSender;
use self::fcm::FcmValidator;
use self::middleware::security_headers_middleware;
use self::pairing::notifier::PairingNotifier;
use self::rate_limit::RateLimitConfig;
use self::rate_limit::SlidingWindowLimiter;
use self::rate_limit::SseConnectionTracker;
use self::rate_limit::rate_limit_middleware;
use self::signing::notifier::SignEventNotifier;
use accept::accept_version_middleware;

#[derive(Debug, Clone)]
pub struct AppState {
    pub repository: Arc<dyn SignatureRepository>,
    pub base_url: String,
    pub signing_key_secret: String,
    pub device_jwt_validity_seconds: u64,
    pub pairing_jwt_validity_seconds: u64,
    pub client_jwt_validity_seconds: u64,
    pub request_jwt_validity_seconds: u64,
    pub unconsumed_pairing_limit: i64,
    pub fcm_validator: Arc<dyn FcmValidator>,
    pub fcm_sender: Arc<dyn FcmSender>,
    pub sse_tracker: SseConnectionTracker,
    pub pairing_notifier: PairingNotifier,
    pub sign_event_notifier: SignEventNotifier,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

pub async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<HealthResponse>, AppError> {
    state
        .repository
        .health_check()
        .await
        .map_err(|error| AppError::from(error).with_instance("/health"))?;

    let _ = state.repository.backend_name();

    Ok(Json(HealthResponse { status: "ok" }))
}

pub fn build_router(state: AppState, rate_limit_config: RateLimitConfig) -> Router {
    let request_id_header = axum::http::header::HeaderName::from_static("x-request-id");
    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            request_id_header.clone(),
        ]);

    let rl_state = rate_limit::middleware::RateLimiterState {
        limiter: Arc::new(SlidingWindowLimiter::new()),
        config: rate_limit_config,
    };

    // Determine the longest window for cleanup eviction.
    let max_window_secs = rl_state
        .config
        .strict
        .window_seconds
        .max(rl_state.config.standard.window_seconds);
    rl_state.limiter.spawn_cleanup_task(
        std::time::Duration::from_secs(max_window_secs),
        std::time::Duration::from_secs(max_window_secs),
    );

    // JSON API routes (with accept_version_middleware).
    let json_routes = Router::new()
        .route("/health", get(health))
        .route("/device", post(device::register_device))
        .route("/device", patch(device::update_device))
        .route("/device", delete(device::delete_device))
        .route("/device/refresh", post(device::refresh_device_jwt))
        .route("/device/public_key", post(device::add_public_key))
        .route("/device/public_key", get(device::list_public_keys))
        .route(
            "/device/public_key/{kid}",
            delete(device::delete_public_key),
        )
        .route("/device/gpg_key", post(device::add_gpg_key))
        .route("/device/gpg_key", get(device::list_gpg_keys))
        .route("/device/gpg_key/{keygrip}", delete(device::delete_gpg_key))
        .route("/pairing/gpg-keys", post(pairing::query_gpg_keys))
        .route("/pairing-token", get(pairing::get_pairing_token))
        .route("/pairing", post(pairing::pair_device))
        .route("/pairing", delete(pairing::delete_pairing_by_daemon))
        .route(
            "/pairing/{pairing_id}",
            delete(pairing::delete_pairing_by_phone),
        )
        .route("/pairing/refresh", post(pairing::refresh_client_jwt))
        .route("/sign-request", post(signing::post_sign_request))
        .route("/sign-request", patch(signing::patch_sign_request))
        .route("/sign-request", get(signing::get_sign_request))
        .route("/sign-request", delete(signing::delete_sign_request))
        .route("/sign-result", post(signing::post_sign_result))
        .layer(axum::middleware::from_fn(accept_version_middleware));

    // SSE routes (no accept_version_middleware).
    let sse_routes = Router::new()
        .route("/pairing-session", get(pairing::get_pairing_session))
        .route("/sign-events", get(signing::get_sign_events));

    json_routes
        .merge(sse_routes)
        .layer(axum::middleware::from_fn_with_state(
            rl_state,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(cors_layer)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .with_state(state)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
