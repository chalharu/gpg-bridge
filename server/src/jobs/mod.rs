use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use crate::config::AppConfig;
use crate::http::signing::notifier::{SignEventData, SignEventNotifier};
use crate::repository::SignatureRepository;

#[cfg(test)]
mod tests;

/// Configuration for the background cleanup scheduler.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    pub interval: Duration,
    pub unpaired_client_max_age: Duration,
    pub device_jwt_validity: Duration,
    pub client_jwt_validity: Duration,
    pub audit_log_approved_retention: Duration,
    pub audit_log_denied_retention: Duration,
    pub audit_log_conflict_retention: Duration,
}

impl CleanupConfig {
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            interval: Duration::from_secs(config.cleanup_interval_seconds),
            unpaired_client_max_age: Duration::from_secs(
                config.unpaired_client_max_age_hours * 3600,
            ),
            device_jwt_validity: Duration::from_secs(config.device_jwt_validity_seconds),
            client_jwt_validity: Duration::from_secs(config.client_jwt_validity_seconds),
            audit_log_approved_retention: Duration::from_secs(
                config.audit_log_approved_retention_seconds,
            ),
            audit_log_denied_retention: Duration::from_secs(
                config.audit_log_denied_retention_seconds,
            ),
            audit_log_conflict_retention: Duration::from_secs(
                config.audit_log_conflict_retention_seconds,
            ),
        }
    }
}

/// Spawn the periodic background cleanup task.
///
/// Returns a `JoinHandle` the caller can use to monitor the task.
pub fn spawn_cleanup_scheduler(
    repo: Arc<dyn SignatureRepository>,
    notifier: SignEventNotifier,
    config: CleanupConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_cleanup_loop(repo, notifier, config))
}

async fn run_cleanup_loop(
    repo: Arc<dyn SignatureRepository>,
    notifier: SignEventNotifier,
    config: CleanupConfig,
) {
    let mut interval = tokio::time::interval(config.interval);
    // The first tick completes immediately; consume it so the first
    // real run happens after one full interval.
    interval.tick().await;

    loop {
        interval.tick().await;
        run_all_jobs(&repo, &notifier, &config).await;
    }
}

async fn run_all_jobs(
    repo: &Arc<dyn SignatureRepository>,
    notifier: &SignEventNotifier,
    config: &CleanupConfig,
) {
    let now = Utc::now();
    let now_str = now.to_rfc3339();

    run_delete_expired_pairings(repo, &now_str).await;
    run_delete_expired_requests(repo, notifier, &now_str).await;
    run_delete_expired_jtis(repo, &now_str).await;
    run_delete_expired_signing_keys(repo, &now_str).await;
    run_delete_unpaired_clients(repo, now, config).await;
    run_delete_expired_device_jwt_clients(repo, now, config).await;
    run_delete_expired_client_jwt_pairings(repo, now, config).await;
    run_delete_expired_audit_logs(repo, now, config).await;
}

async fn run_delete_expired_pairings(repo: &Arc<dyn SignatureRepository>, now: &str) {
    match repo.delete_expired_pairings(now).await {
        Ok(n) if n > 0 => info!(deleted = n, "expired pairings cleaned up"),
        Err(e) => warn!(error = %e, "failed to delete expired pairings"),
        _ => {}
    }
}

async fn run_delete_expired_requests(
    repo: &Arc<dyn SignatureRepository>,
    notifier: &SignEventNotifier,
    now: &str,
) {
    match repo.delete_expired_requests(now).await {
        Ok(incomplete_ids) => {
            for request_id in &incomplete_ids {
                notifier.notify(
                    request_id,
                    SignEventData {
                        signature: None,
                        status: "expired".into(),
                    },
                );
            }
            if !incomplete_ids.is_empty() {
                info!(
                    notified = incomplete_ids.len(),
                    "expired requests cleaned up (SSE events sent)",
                );
            }
        }
        Err(e) => warn!(error = %e, "failed to delete expired requests"),
    }
}

async fn run_delete_expired_jtis(repo: &Arc<dyn SignatureRepository>, now: &str) {
    match repo.delete_expired_jtis(now).await {
        Ok(n) if n > 0 => info!(deleted = n, "expired JTIs cleaned up"),
        Err(e) => warn!(error = %e, "failed to delete expired JTIs"),
        _ => {}
    }
}

async fn run_delete_expired_signing_keys(repo: &Arc<dyn SignatureRepository>, now: &str) {
    match repo.delete_expired_signing_keys(now).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, "expired signing keys cleaned up");
        }
        Err(e) => warn!(error = %e, "failed to delete expired signing keys"),
        _ => {}
    }
}

/// Compute a cutoff timestamp by subtracting `duration` from `now`.
///
/// Returns `None` (with a warning log) when the subtraction overflows.
fn compute_cutoff(now: chrono::DateTime<Utc>, duration: Duration, label: &str) -> Option<String> {
    let chrono_dur = chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::MAX);
    match now.checked_sub_signed(chrono_dur) {
        Some(t) => Some(t.to_rfc3339()),
        None => {
            warn!("overflow computing {label} cutoff; skipping");
            None
        }
    }
}

async fn run_delete_unpaired_clients(
    repo: &Arc<dyn SignatureRepository>,
    now: chrono::DateTime<Utc>,
    config: &CleanupConfig,
) {
    let Some(cutoff) = compute_cutoff(now, config.unpaired_client_max_age, "unpaired-client")
    else {
        return;
    };
    match repo.delete_unpaired_clients(&cutoff).await {
        Ok(n) if n > 0 => info!(deleted = n, "unpaired clients cleaned up"),
        Err(e) => warn!(error = %e, "failed to delete unpaired clients"),
        _ => {}
    }
}

async fn run_delete_expired_device_jwt_clients(
    repo: &Arc<dyn SignatureRepository>,
    now: chrono::DateTime<Utc>,
    config: &CleanupConfig,
) {
    let Some(cutoff) = compute_cutoff(now, config.device_jwt_validity, "device-JWT") else {
        return;
    };
    match repo.delete_expired_device_jwt_clients(&cutoff).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, "expired device-JWT clients cleaned up");
        }
        Err(e) => {
            warn!(error = %e, "failed to delete expired device-JWT clients");
        }
        _ => {}
    }
}

async fn run_delete_expired_client_jwt_pairings(
    repo: &Arc<dyn SignatureRepository>,
    now: chrono::DateTime<Utc>,
    config: &CleanupConfig,
) {
    let Some(cutoff) = compute_cutoff(now, config.client_jwt_validity, "client-JWT") else {
        return;
    };
    match repo.delete_expired_client_jwt_pairings(&cutoff).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, "expired client-JWT pairings cleaned up");
        }
        Err(e) => {
            warn!(error = %e, "failed to delete expired client-JWT pairings");
        }
        _ => {}
    }
}

async fn run_delete_expired_audit_logs(
    repo: &Arc<dyn SignatureRepository>,
    now: chrono::DateTime<Utc>,
    config: &CleanupConfig,
) {
    let Some(approved_cutoff) = compute_cutoff(
        now,
        config.audit_log_approved_retention,
        "audit-log approved",
    ) else {
        return;
    };
    let Some(denied_cutoff) =
        compute_cutoff(now, config.audit_log_denied_retention, "audit-log denied")
    else {
        return;
    };
    let Some(conflict_cutoff) = compute_cutoff(
        now,
        config.audit_log_conflict_retention,
        "audit-log conflict",
    ) else {
        return;
    };
    match repo
        .delete_expired_audit_logs(&approved_cutoff, &denied_cutoff, &conflict_cutoff)
        .await
    {
        Ok(n) if n > 0 => {
            info!(deleted = n, "expired audit logs cleaned up");
        }
        Err(e) => {
            warn!(error = %e, "failed to delete expired audit logs");
        }
        _ => {}
    }
}
