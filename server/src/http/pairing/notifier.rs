use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::watch;

/// Data sent via the SSE `paired` event.
#[derive(Debug, Clone, Serialize)]
pub struct PairedEventData {
    pub client_jwt: String,
    pub client_id: String,
}

/// Manages notification channels for pending pairing SSE sessions.
///
/// Each pairing_id maps to a `watch::Sender` that the SSE handler
/// subscribes to. When POST /pairing completes, it sends
/// `PairedEventData` through the channel.
#[derive(Clone)]
pub struct PairingNotifier {
    channels: Arc<Mutex<HashMap<String, watch::Sender<Option<PairedEventData>>>>>,
}

impl Default for PairingNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingNotifier {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Subscribe to pairing completion for `pairing_id`.
    ///
    /// Creates a watch channel and stores the sender. Returns a
    /// receiver the SSE handler can await on.
    pub fn subscribe(&self, pairing_id: &str) -> watch::Receiver<Option<PairedEventData>> {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        if let Some(sender) = channels.get(pairing_id) {
            return sender.subscribe();
        }
        let (tx, rx) = watch::channel(None);
        channels.insert(pairing_id.to_owned(), tx);
        rx
    }

    /// Notify the SSE handler that pairing is complete.
    ///
    /// Sends the paired event data and removes the channel.
    pub fn notify(&self, pairing_id: &str, data: PairedEventData) {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        if let Some(sender) = channels.remove(pairing_id) {
            let _ = sender.send(Some(data));
        }
    }

    /// Remove a subscription without sending data (e.g. on disconnect).
    ///
    /// This removes the entire watch channel for `pairing_id`. The design
    /// assumes at most one SSE subscriber per pairing (enforced by
    /// `SseConnectionTracker` with `max_per_key = 1`). If that invariant
    /// changes, this method should use reference counting instead.
    pub fn unsubscribe(&self, pairing_id: &str) {
        let mut channels = self.channels.lock().expect("notifier lock poisoned");
        channels.remove(pairing_id);
    }
}

impl std::fmt::Debug for PairingNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.channels.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("PairingNotifier")
            .field("active_channels", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_notify_delivers_data() {
        let notifier = PairingNotifier::new();
        let rx = notifier.subscribe("pair-1");

        notifier.notify(
            "pair-1",
            PairedEventData {
                client_jwt: "jwt-abc".into(),
                client_id: "cid-1".into(),
            },
        );

        // Sender is dropped after notify, but the value is still readable.
        let data = rx.borrow().clone().unwrap();
        assert_eq!(data.client_jwt, "jwt-abc");
        assert_eq!(data.client_id, "cid-1");
    }

    #[test]
    fn notify_without_subscriber_is_noop() {
        let notifier = PairingNotifier::new();
        notifier.notify(
            "pair-x",
            PairedEventData {
                client_jwt: "jwt".into(),
                client_id: "cid".into(),
            },
        );
    }

    #[test]
    fn unsubscribe_removes_channel() {
        let notifier = PairingNotifier::new();
        let _rx = notifier.subscribe("pair-1");
        notifier.unsubscribe("pair-1");

        notifier.notify(
            "pair-1",
            PairedEventData {
                client_jwt: "jwt".into(),
                client_id: "cid".into(),
            },
        );
    }

    #[test]
    fn debug_format_shows_active_channels() {
        let notifier = PairingNotifier::new();
        let _rx = notifier.subscribe("pair-1");
        let debug = format!("{notifier:?}");
        assert!(debug.contains("active_channels: 1"));
    }

    #[test]
    fn subscribe_returns_existing_receiver() {
        let notifier = PairingNotifier::new();
        let _rx1 = notifier.subscribe("pair-1");
        let rx2 = notifier.subscribe("pair-1");

        notifier.notify(
            "pair-1",
            PairedEventData {
                client_jwt: "jwt-2".into(),
                client_id: "cid-2".into(),
            },
        );

        // Sender is dropped after notify, but the value is still readable.
        let data = rx2.borrow().clone().unwrap();
        assert_eq!(data.client_jwt, "jwt-2");
    }
}
