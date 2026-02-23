-- jtis table: tracks consumed JWT IDs for replay prevention
CREATE TABLE IF NOT EXISTS jtis (
    jti     TEXT PRIMARY KEY,
    expired TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jtis_expired ON jtis (expired);
