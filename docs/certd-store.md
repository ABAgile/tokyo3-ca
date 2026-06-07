# certd persistent store — schema & renewal/anti-theft protocol

The central certd store that backs `policy.Store` / `mtls.Store` /
`krl.Store` (replacing the in-memory + JSON-file-seeded defaults), plus the
`active_workload_cert` table behind the X.509 cert-renewal anti-theft guard.

Selected with `CERTD_DATABASE_URL`: a Postgres DSN, or `sqlite:<path>`.
Unset ⇒ the in-memory/file path (dev default). Implemented under
`internal/store/` with a shared interface and two backends.

## Scope & invariants

- **This is certd's central store only.** Per-host cert-agentd state (its
  own bundles, on-disk cert serial) is separate local state on each agent
  host, not this DB.
- **No private key material in this DB, ever.** The CA signing key lives in
  `CERTD_CA_KEY_FILE` / KMS (`RemoteSigner`); issued leaf keys never reach
  certd. This DB holds policy + registries + revocation + the active-cert
  anti-rollback state. (Stated as a header comment in the migrations so
  nobody adds a `private_key` column.)
- **Two serial namespaces, never one column.** SSH cert serial is a
  protocol-fixed `uint64`; X.509 serial is a `*big.Int` (≤160-bit, random
  per CA/B-Forum hygiene). They share the *word* "serial" but are NOT
  interchangeable values — separate columns/tables. Both are stored as
  **decimal TEXT** so the full range survives (uint64 and big-int alike,
  no signed-64 overflow).
- **UUIDs (if used) are database primary keys, not cert serials.** Generate
  UUIDv7 app-side (`github.com/google/uuid` `NewV7()`) for portability —
  SQLite has no UUID type (store `TEXT`/`BLOB`) and Postgres only gained a
  native `uuidv7()` generator in PG 18.

## Engine: Postgres (production) + SQLite (dev/test)

The tokyo3-auth dual-backend pattern (`auth/internal/store`): one shared
interface, two backends behind it.

- **Postgres** (pgx/v5) is the production store, so certd can scale
  active-active and reuse the platform's existing PG ops/DR.
- **SQLite** (pure-Go modernc, no cgo) is the dev-rig + unit-test backend:
  fast, no server, runs the store acceptance suite offline.

NATS-KV was considered and rejected as the *authoritative* store (couples CA
state to the bus; no queries). Each backend has its own `migrations/`
(placeholder + type dialect differ; JSON stored as TEXT in both for parity —
promote PG to JSONB later if the portal needs to query into it). Reads
**fail closed**.

Because `policy.Store` and `mtls.Store` both declare `All()` with different
return types, one Go type can't satisfy both — so the backends use an
**accessor pattern**: the composite `store.Store` exposes
`Roles() / Principals() / Revocations() / ActiveCerts() / Close()`, each
returning a sub-store.

## Schema

```sql
-- 1. ROLES  (policy.Store) -------------------------------------------------
--   group_claim is NOT unique: RolesForGroups aggregates all roles for a
--   claim. name is the identity (PK). Multi-valued fields are JSON to mirror
--   the JSON-file seed; normalize into child tables only if you ever need to
--   query *into* the patterns.
CREATE TABLE roles (
    name                      TEXT PRIMARY KEY,
    group_claim               TEXT NOT NULL,
    allowed_principals        TEXT NOT NULL DEFAULT '[]', -- JSON array
    host_patterns             TEXT NOT NULL DEFAULT '[]', -- JSON array (path.Match globs)
    spiffe_patterns           TEXT NOT NULL DEFAULT '[]', -- JSON array (path.Match globs)
    default_extensions        TEXT NOT NULL DEFAULT '{}', -- JSON object string->string
    max_user_cert_ttl_seconds INTEGER NOT NULL DEFAULT 0, -- 0 ⇒ no per-role cap
    max_host_cert_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    max_x509_cert_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at                TEXT NOT NULL
);
CREATE INDEX roles_group_claim_idx ON roles (group_claim);

-- 2. PRINCIPALS  (mtls.Store) ----------------------------------------------
--   Keyed by the registered SAN (the Lookup key). name is the audit handle
--   and is NOT unique — one workload may register several SANs (several rows).
CREATE TABLE principals (
    san        TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    groups     TEXT NOT NULL DEFAULT '[]', -- JSON array of group claims
    updated_at TEXT NOT NULL
);
CREATE INDEX principals_name_idx ON principals (name);

-- 3. SSH_REVOCATIONS  (krl.Store) — SSH-ONLY ------------------------------
--   OpenSSH KRL, consumed by ssh-proxyd's IsRevoked gate. serial is the SSH
--   cert serial (uint64, decimal TEXT); key_id is the SSH cert key id. X.509
--   has NO revocation here (x509engine defers CRL) — workload certs rely on
--   short TTL + the active_workload_cert guard below.
CREATE TABLE ssh_revocations (
    id         INTEGER PRIMARY KEY,        -- surrogate
    serial     TEXT,                       -- SSH uint64 as decimal TEXT
    key_id     TEXT,
    reason     TEXT NOT NULL DEFAULT '',
    revoker    TEXT NOT NULL DEFAULT '',
    revoked_at TEXT NOT NULL,
    CHECK (serial IS NOT NULL OR key_id IS NOT NULL)  -- matches ErrEmptyRevocation
);
CREATE UNIQUE INDEX ssh_revocations_serial_idx ON ssh_revocations (serial) WHERE serial IS NOT NULL;
CREATE UNIQUE INDEX ssh_revocations_key_id_idx ON ssh_revocations (key_id) WHERE key_id IS NOT NULL;
-- Revoke is idempotent (delete-then-insert on the present dimension).

-- 4. ACTIVE_WORKLOAD_CERT — X.509 renewal anti-theft state -----------------
--   Per identity: the currently-valid serial plus a one-step grace
--   (previous) covering the rotation/crash window. EQUALITY check, not
--   magnitude — so serials stay random. locked_at/locked_serial stamp a
--   reuse-detection escalation (see protocol). Serials are decimal big-int
--   TEXT; previous_* are NULL once collapsed.
CREATE TABLE active_workload_cert (
    identity           TEXT PRIMARY KEY,   -- SPIFFE URI
    current_serial     TEXT NOT NULL,      -- the cert valid right now (random OK)
    current_not_after  TEXT NOT NULL,
    previous_serial    TEXT,               -- one-step grace; NULL once acked/collapsed
    previous_not_after TEXT,
    updated_at         TEXT NOT NULL,
    locked_at          TEXT,               -- set on reuse detection (migration 0005)
    locked_serial      TEXT                -- the offending serial, kept for forensics
);
```

Plus a `schema_migrations` table per backend.

### Store-method → query map

| Method | Query |
|---|---|
| `policy.RolesForGroups(groups)` | `SELECT * FROM roles WHERE group_claim IN (…)` |
| `policy` CRUD / `All` | by `name` PK |
| `mtls.Lookup(sans)` | `SELECT * FROM principals WHERE san IN (…)`; pick by **presented order** in app |
| `krl.IsRevoked(serial,keyID)` | `SELECT 1 FROM ssh_revocations WHERE serial=? OR key_id=? LIMIT 1` (error ⇒ treat as revoked) |
| `krl.Revoke` | delete-then-insert on present dimension |
| `krl.Snapshot` | `SELECT * ORDER BY revoked_at` |
| active-cert guard | `ActiveCerts().Get/Upsert/Delete/Lock/AdoptCurrent` — see protocol |

## Renewal / anti-theft protocol (active_workload_cert)

Refresh-token rotation with reuse detection (RFC 6819 §5.2.2.3), applied to
X.509 workload certs. Equality-based, so serials stay random.

**State:** per identity, `{current_serial, previous_serial?}` — at most two
live serials, plus an optional lock stamp.

**Renew:** the agent authenticates (mTLS) and presents the serial of the
cert it holds (`current_serial` in the sign request; cert-agentd reads it
from the on-disk cert, so it is stateless across restarts). certd accepts
only when the presented serial ∈ `{current, previous}` (or there is no row
yet — first issuance). It mints `new`, sets `previous := the serial
presented`, `current := new`, and `Upsert`s before returning `new`. The
record write must succeed or the request fails — otherwise a later rollback
could slip past the guard.

**Adopt / ack:** the agent calls `POST /api/v1/x509/adopt` with its identity
+ the current serial once it has durably persisted the new cert.
`AdoptCurrent` clears `previous_*` IFF the serial is the recorded current
and the row is not locked. This collapses the dual-valid window from "until
the next renewal" to "until this ack" — shrinking the window a rotated-from
serial stays acceptable. Adoption is also implicit: the agent's next
authenticated renew with `new` proves adoption. The endpoint mints nothing
and cannot escalate, so it needs authentication but not role authorization —
the `serial == current` check is the real gate (only a holder of the current
cert knows its serial).

**Crash / network interruption:** the agent never adopts `new`; on restart
it still holds the prior cert (still in `{current, previous}`) and renews
with it. certd discards the orphaned un-adopted serial and mints a fresh
one. No lockout.

**Reuse detection — lock escalation (the part that makes it *protection*,
not just rotation):** a renewal presenting a serial that is **neither
current nor previous**, while the recorded current cert is **still valid**,
is treated as a possible clone. certd **locks the identity**
(`locked_at` / `locked_serial`) and denies with `403`, emitting a
`x509.workload_cert.locked` audit event. A locked identity stays denied
**even past expiry** (the auto-re-enroll path does not fire) until an
operator clears the row (`ActiveCerts().Delete`). The lock is attempted
first and the request denied even if the lock write fails.

**Lockout recovery / re-enroll:** if the recorded current cert has
**expired**, a renewal that cannot present a matching serial (including the
lost-cert empty-serial case) is allowed to re-enroll — an expired cert is no
credential, so the guard is moot and normal caller-auth + role policy still
gate the request. Emits `x509.workload_cert.reenroll`; auto-heals within one
cert TTL. An operator can also `Delete` the row to reset immediately.

### What it does and does not protect

- ✅ Crash/network resilient (one-step grace); ✅ bounds a superseded stolen
  cert's life to one renewal cycle; ✅ a clone that renews trips the lock and
  freezes the identity for operator review.
- ⚠️ Does **not** prevent use of a freshly-stolen *current* key-pair — that
  is a race inherent to bearer credentials. You get **detection** (the lock
  fires; the legit agent is frozen, surfacing the incident), not prevention.
- A clone that only *uses* the cert (never renews) is invisible here — only
  **short TTL** limits that.

### Hard dependencies (without these the mechanism is meaningless)

1. **Persistent store** — the protocol is pure state over
   `active_workload_cert`. In-memory it resets on restart and the guard is
   void. The guard is opt-in with the persistent store (wired only when
   `CERTD_DATABASE_URL` is set).
2. **Atomic bundle persist on the agent** (`output.WriteBundleAtomic`,
   key-first/cert-last) so a sloppily-retained old cert can't be re-presented
   and look like a clone. The real consistency guarantee is **read-side**:
   the consumer's loader verifies the pair (`tls.LoadX509KeyPair`) and keeps
   the last-known-good on mismatch — base `tls.CertLoader` / `tls/reloader`
   already do.
3. **Short workload-cert TTL** — the only limiter on immediate misuse of a
   stolen current cert, and what makes expiry-based re-enroll recovery fast.
4. **Hardened bootstrap re-enroll** — the recovery path is also the bypass;
   if bootstrap auth is weak, all of this is moot.

### Key-pair rotation

`renew.Config.RotateKey` mints a fresh keypair every renewal (bundled
key+cert write each cycle); **default OFF** — opt-in per workload
(`rotate_key` in `CERT_AGENTD_WORKLOADS_FILE`, `CERT_AGENTD_ROTATE_KEY` for
the agent's own cert). Rotation needs a consumer that verifies/reloads the
pair (or a reload-after-write signal); file-reading servers like Postgres
can't safely reload a rotating pair, so they stay on the stable-key path
(cert-only rotation). The renewer exposes an `OnRenewed` hook as the
reload-after-write signal point for consumers that need it.

## Not implemented (deliberate)

- **`issued_certs` ledger.** Originally sketched to let reuse-detection
  distinguish a *known-retired* serial (→ compromise) from a *never-issued*
  one (→ plain reject). Superseded by the lock-on-reuse stance above:
  **any** serial outside `{current, previous}` (while the current cert is
  valid) locks the identity, so the distinction is unnecessary. The audit
  stream already records issuance for forensics. Revisit only if finer
  alerting (retired vs fabricated) is wanted.
- **X.509 CRL / revocation.** `x509engine` defers it; short TTL + the
  active-cert guard are the containment story for workload certs.
- **Combined-PEM agent output / fully wired reload-after-write.** The
  `OnRenewed` hook exists; wiring it to actively signal a specific naive
  server consumer is left to that consumer's integration.
