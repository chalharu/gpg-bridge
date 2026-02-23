-- audit_log table: immutable record of security-relevant events
CREATE TABLE IF NOT EXISTS audit_log (
    log_id               TEXT PRIMARY KEY,
    timestamp            TEXT NOT NULL,
    event_type           TEXT NOT NULL
        CHECK (event_type IN (
            'sign_request_created', 'sign_request_dispatched',
            'sign_approved', 'sign_denied', 'sign_device_unavailable',
            'sign_unavailable', 'sign_expired', 'sign_cancelled',
            'sign_result_conflict')),
    request_id           TEXT NOT NULL,
    request_ip           TEXT,
    target_client_ids    TEXT,       -- JSON array (nullable)
    responding_client_id TEXT,
    error_code           TEXT,
    error_message        TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp  ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id ON audit_log (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type);
