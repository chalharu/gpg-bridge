-- signing_keys table: server-side JWT signing key pairs for rotation
CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_key TEXT NOT NULL,       -- encrypted JWK
    public_key  TEXT NOT NULL,       -- JWK
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT FALSE
);

-- Partial unique index: enforce at most one active signing key at the DB level
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_active_unique
    ON signing_keys (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_signing_keys_expires_at ON signing_keys (expires_at);
