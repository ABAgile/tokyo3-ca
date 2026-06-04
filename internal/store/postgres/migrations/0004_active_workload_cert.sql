-- certd store (postgres), migration 0004: per-identity X.509 workload-cert
-- rotation state for the renewal/anti-theft guard (see
-- certd-store-design.md). Serials are decimal big-int TEXT (X.509 serials
-- exceed uint64). previous_* are the one-step grace; NULL once collapsed.
CREATE TABLE IF NOT EXISTS active_workload_cert (
    identity           TEXT PRIMARY KEY,
    current_serial     TEXT NOT NULL,
    current_not_after  TEXT NOT NULL,
    previous_serial    TEXT,
    previous_not_after TEXT,
    updated_at         TEXT NOT NULL
);
