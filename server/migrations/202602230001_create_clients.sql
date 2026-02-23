-- clients table: stores registered mobile client devices
CREATE TABLE IF NOT EXISTS clients (
    client_id   TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    device_token TEXT NOT NULL,
    device_jwt_issued_at TEXT NOT NULL,
    public_keys TEXT NOT NULL,   -- JSON: JWK Set
    default_kid TEXT NOT NULL,
    gpg_keys    TEXT NOT NULL    -- JSON: array of GPG key metadata
);

-- Indexes for background cleanup jobs (see requirements 6.3)
CREATE INDEX IF NOT EXISTS idx_clients_created_at          ON clients (created_at);
CREATE INDEX IF NOT EXISTS idx_clients_device_jwt_issued_at ON clients (device_jwt_issued_at);
