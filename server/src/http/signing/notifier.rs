use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::watch;

/// Data sent via the SSE `signature` event.
#[derive(Debug, Clone, Serialize)]
pub struct SignEventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub status: String,
}

/// Manages notification channels for pending sign-event SSE sessions.
///
/// Each request_id maps to a `watch::Sender` that the SSE handler
/// subscribes to. When POST /sign-result completes (or DELETE /sign-request
/// cancels), it sends `SignEventData` through the channel.
#[derive(Clone)]
pub struct SignEventNotifier {
    channels: Arc<Mutex<HashMap<String, watch::Sender<Option<SignEventData>>>>>,
}

impl Default for SignEventNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SignEventNotifier {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Subscribe to sign-event completion for `request_id`.
    ///
    /// Creates a watch channel and stores the sender. Returns a
    /// receiver the SSE handler can await on.
    pub fn subscribe(&self, request_id: &str) -> watch::Receiver<Option<SignEventData>> {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        if let Some(sender) = channels.get(request_id) {
            return sender.subscribe();
        }
        let (tx, rx) = watch::channel(None);
        channels.insert(request_id.to_owned(), tx);
        rx
    }

    /// Notify the SSE handler that a sign event has occurred.
    ///
    /// Sends the event data and removes the channel.
    pub fn notify(&self, request_id: &str, data: SignEventData) {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        if let Some(sender) = channels.remove(request_id) {
            let _ = sender.send(Some(data));
        }
    }

    /// Remove a subscription without sending data (e.g. on disconnect).
    ///
    /// This removes the entire watch channel for `request_id`. The design
    /// assumes at most one SSE subscriber per request (enforced by
    /// `SseConnectionTracker` with `max_per_key = 1`). If that invariant
    /// changes, this method should use reference counting instead.
    pub fn unsubscribe(&self, request_id: &str) {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        channels.remove(request_id);
    }
}

impl std::fmt::Debug for SignEventNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.channels.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("SignEventNotifier")
            .field("active_channels", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_notify_delivers_data() {
        let notifier = SignEventNotifier::new();
        let rx = notifier.subscribe("req-1");

        notifier.notify(
            "req-1",
            SignEventData {
                signature: Some("sig-abc".into()),
                status: "approved".into(),
            },
        );

        let data = rx.borrow().clone().unwrap();
        assert_eq!(data.signature.as_deref(), Some("sig-abc"));
        assert_eq!(data.status, "approved");
    }

    #[test]
    fn notify_without_subscriber_is_noop() {
        let notifier = SignEventNotifier::new();
        notifier.notify(
            "req-x",
            SignEventData {
                signature: None,
                status: "denied".into(),
            },
        );
    }

    #[test]
    fn unsubscribe_removes_channel() {
        let notifier = SignEventNotifier::new();
        let _rx = notifier.subscribe("req-1");
        notifier.unsubscribe("req-1");

        notifier.notify(
            "req-1",
            SignEventData {
                signature: None,
                status: "denied".into(),
            },
        );
    }

    #[test]
    fn debug_format_shows_active_channels() {
        let notifier = SignEventNotifier::new();
        let _rx = notifier.subscribe("req-1");
        let debug = format!("{notifier:?}");
        assert!(debug.contains("active_channels: 1"));
    }

    #[test]
    fn subscribe_returns_existing_receiver() {
        let notifier = SignEventNotifier::new();
        let _rx1 = notifier.subscribe("req-1");
        let rx2 = notifier.subscribe("req-1");

        notifier.notify(
            "req-1",
            SignEventData {
                signature: None,
                status: "cancelled".into(),
            },
        );

        let data = rx2.borrow().clone().unwrap();
        assert_eq!(data.status, "cancelled");
    }

    #[test]
    fn default_creates_new_instance() {
        let notifier = SignEventNotifier::default();
        let debug = format!("{notifier:?}");
        assert!(debug.contains("active_channels: 0"));
    }

    #[test]
    fn serialization_skips_none_signature() {
        let data = SignEventData {
            signature: None,
            status: "denied".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.contains("signature"));
        assert!(json.contains("\"status\":\"denied\""));
    }

    #[test]
    fn serialization_includes_some_signature() {
        let data = SignEventData {
            signature: Some("sig-data".into()),
            status: "approved".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"signature\":\"sig-data\""));
        assert!(json.contains("\"status\":\"approved\""));
    }
}
