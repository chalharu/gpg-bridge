-- pairings table: tracks short-lived daemon–client pairing sessions
CREATE TABLE IF NOT EXISTS pairings (
    pairing_id  TEXT PRIMARY KEY,
    expired     TEXT NOT NULL,
    client_id   TEXT,
    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pairings_expired   ON pairings (expired);
CREATE INDEX IF NOT EXISTS idx_pairings_client_id ON pairings (client_id);
