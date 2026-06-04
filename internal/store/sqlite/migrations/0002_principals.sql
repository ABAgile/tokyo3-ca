-- certd store (sqlite), migration 0002: mTLS cert-principal registry.
-- Keyed by the registered SAN (mtls.Principal.MatchedSAN); name is the
-- audit handle (NOT unique — a workload may register several SANs).
CREATE TABLE IF NOT EXISTS principals (
    san        TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    groups     TEXT NOT NULL DEFAULT '[]', -- JSON array of group claims
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS principals_name_idx ON principals (name);
