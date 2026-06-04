-- certd store (postgres), migration 0003: SSH KRL (krl.Store). SSH-only —
-- X.509 has no revocation (short TTL + the active-cert guard instead).
-- serial is the SSH cert serial stored as TEXT (decimal) so the full
-- uint64 range survives; either serial or key_id may be NULL, never both.
CREATE TABLE IF NOT EXISTS ssh_revocations (
    id         BIGSERIAL PRIMARY KEY,
    serial     TEXT,
    key_id     TEXT,
    reason     TEXT NOT NULL DEFAULT '',
    revoker    TEXT NOT NULL DEFAULT '',
    revoked_at TEXT NOT NULL,
    CHECK (serial IS NOT NULL OR key_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS ssh_revocations_serial_idx ON ssh_revocations (serial) WHERE serial IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ssh_revocations_key_id_idx ON ssh_revocations (key_id) WHERE key_id IS NOT NULL;
