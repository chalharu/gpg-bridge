CREATE TABLE IF NOT EXISTS sign_requests (
    id BIGINT PRIMARY KEY,
    key_fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
