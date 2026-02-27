use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::WatchStream;

use crate::error::AppError;
use crate::http::AppState;
use crate::repository::SigningKeyRow;

use super::helpers::build_client_jwt_token;
use super::notifier::PairedEventData;

const HEARTBEAT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Immediate paired response (already paired)
// ---------------------------------------------------------------------------

pub fn build_immediate_response(
    state: &AppState,
    signing_key: &SigningKeyRow,
    client_id: String,
    pairing_id: &str,
    guard: crate::http::rate_limit::SseConnectionGuard,
) -> Result<Response, AppError> {
    let client_jwt = build_client_jwt_token(state, signing_key, &client_id, pairing_id)?;
    let data = PairedEventData {
        client_jwt,
        client_id,
    };
    let json = serde_json::to_string(&data).expect("PairedEventData serialization");
    // Hold the guard inside the stream so the SSE slot stays reserved
    // until the response body is fully consumed by the client.
    let stream = futures_util::stream::unfold(Some((guard, json)), |slot| async move {
        let (g, json) = slot?;
        let event = Event::default().event("paired").data(json);
        Some((Ok::<_, Infallible>(event), Some((g, String::new()))))
    });
    // Take only the first event (the paired event); drop guard after.
    let stream = stream.take(1);

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new())
        .into_response())
}

// ---------------------------------------------------------------------------
// Waiting SSE stream (not yet paired)
// ---------------------------------------------------------------------------

pub fn build_waiting_response(
    state: AppState,
    pairing_id: String,
    signing_key: SigningKeyRow,
    guard: crate::http::rate_limit::SseConnectionGuard,
    rx: tokio::sync::watch::Receiver<Option<PairedEventData>>,
    expiry: DateTime<Utc>,
) -> Response {
    let stream = async_stream(state, pairing_id, signing_key, rx, guard, expiry);

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(HEARTBEAT_SECS))
                .event(Event::default().event("heartbeat")),
        )
        .into_response()
}

fn async_stream(
    state: AppState,
    pairing_id: String,
    signing_key: SigningKeyRow,
    rx: tokio::sync::watch::Receiver<Option<PairedEventData>>,
    guard: crate::http::rate_limit::SseConnectionGuard,
    expiry: DateTime<Utc>,
) -> impl tokio_stream::Stream<Item = Result<Event, Infallible>> {
    futures_util::stream::unfold(
        StreamState::new(state, pairing_id, signing_key, rx, guard, expiry),
        |mut ctx| async move { ctx.next_event().await.map(|event| (event, ctx)) },
    )
}

struct StreamState {
    state: AppState,
    pairing_id: String,
    signing_key: SigningKeyRow,
    watch: WatchStream<Option<PairedEventData>>,
    _guard: crate::http::rate_limit::SseConnectionGuard,
    expiry: DateTime<Utc>,
    done: bool,
}

impl StreamState {
    fn new(
        state: AppState,
        pairing_id: String,
        signing_key: SigningKeyRow,
        rx: tokio::sync::watch::Receiver<Option<PairedEventData>>,
        guard: crate::http::rate_limit::SseConnectionGuard,
        expiry: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            pairing_id,
            signing_key,
            watch: WatchStream::new(rx),
            _guard: guard,
            expiry,
            done: false,
        }
    }

    async fn next_event(&mut self) -> Option<Result<Event, Infallible>> {
        if self.done {
            return None;
        }

        // Compute remaining time until pairing expiry.
        let remaining = (self.expiry - Utc::now()).to_std().unwrap_or_default();
        if remaining.is_zero() {
            self.done = true;
            return None;
        }

        tokio::select! {
            biased;
            item = self.watch.next() => match item {
                Some(Some(data)) => {
                    self.done = true;
                    Some(Ok(paired_event(&data)))
                }
                Some(None) => {
                    // Initial None from watch channel — return an
                    // empty comment to keep the stream alive.
                    Some(Ok(Event::default().comment("")))
                }
                None => {
                    // Channel closed. Check DB as fallback.
                    self.done = true;
                    let event = self
                        .check_db_fallback()
                        .await
                        .map(|data| paired_event(&data))
                        .unwrap_or_else(|| Event::default().comment("closed"));
                    Some(Ok(event))
                }
            },
            () = tokio::time::sleep(remaining) => {
                // Pairing expired — terminate the stream.
                self.done = true;
                None
            }
        }
    }

    async fn check_db_fallback(&self) -> Option<PairedEventData> {
        let pairing = self
            .state
            .repository
            .get_pairing_by_id(&self.pairing_id)
            .await
            .ok()??;
        let client_id = pairing.client_id?;
        let client_jwt =
            build_client_jwt_token(&self.state, &self.signing_key, &client_id, &self.pairing_id)
                .ok()?;
        Some(PairedEventData {
            client_jwt,
            client_id,
        })
    }
}

fn paired_event(data: &PairedEventData) -> Event {
    let json = serde_json::to_string(data).expect("PairedEventData serialization");
    Event::default().event("paired").data(json)
}

/// Cleanup is handled exclusively in `Drop` to avoid double unsubscribe.
impl Drop for StreamState {
    fn drop(&mut self) {
        self.state.pairing_notifier.unsubscribe(&self.pairing_id);
    }
}
