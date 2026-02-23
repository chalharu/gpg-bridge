-- requests table: GPG signing requests from daemons
CREATE TABLE IF NOT EXISTS requests (
    request_id             TEXT PRIMARY KEY,
    status                 TEXT NOT NULL
        CHECK (status IN ('created', 'pending', 'approved', 'denied', 'unavailable')),
    expired                TEXT NOT NULL,
    signature              TEXT,
    client_ids             TEXT NOT NULL,        -- JSON array of client-id strings
    daemon_public_key      TEXT NOT NULL,        -- JSON: JWK
    daemon_enc_public_key  TEXT NOT NULL,        -- JSON: JWK
    pairing_ids            TEXT NOT NULL,        -- JSON object {client_id: pairing_id}
    e2e_kids               TEXT NOT NULL,        -- JSON object {client_id: kid}
    encrypted_payloads     TEXT,                 -- JSON object (nullable)
    unavailable_client_ids TEXT NOT NULL DEFAULT '[]', -- JSON array

    -- Status / payload / signature consistency constraints
    CHECK (
        (status = 'created'     AND encrypted_payloads IS NULL     AND signature IS NULL)
        OR (status = 'pending'  AND encrypted_payloads IS NOT NULL AND signature IS NULL)
        OR (status = 'approved' AND encrypted_payloads IS NOT NULL AND signature IS NOT NULL)
        OR (status = 'denied'   AND encrypted_payloads IS NOT NULL AND signature IS NULL)
        OR (status = 'unavailable' AND encrypted_payloads IS NOT NULL AND signature IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_requests_expired ON requests (expired);
CREATE INDEX IF NOT EXISTS idx_requests_status  ON requests (status);
