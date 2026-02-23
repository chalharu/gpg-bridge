-- client_pairings junction table: maps clients to their paired daemons
-- Note: No FK to pairings because pairings records are short-lived (expired after ~300s)
-- while client_pairings persist for the lifetime of the pairing relationship.
-- pairing_id is kept as a logical identifier only.
CREATE TABLE IF NOT EXISTS client_pairings (
    client_id             TEXT NOT NULL,
    pairing_id            TEXT NOT NULL,
    client_jwt_issued_at  TEXT NOT NULL,
    PRIMARY KEY (client_id, pairing_id),
    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_client_pairings_pairing_id           ON client_pairings (pairing_id);
CREATE INDEX IF NOT EXISTS idx_client_pairings_client_jwt_issued_at ON client_pairings (client_jwt_issued_at);
