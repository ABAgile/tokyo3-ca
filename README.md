# tokyo3-ca

Certificate authority for internal platform. Issues short-lived SSH
certificates (user / host / per-session) and X.509 / SPIFFE workload identity
certificates against an OIDC-group-driven role table. Integrates with an
external OIDC IdP (for human authentication) and `vaultd` (secret store +
envelope crypto) under the same application suite platform.

This repo ships two binaries:

| Binary        | Role                                                                                         |
|---------------|----------------------------------------------------------------------------------------------|
| `certd`       | Central CA service. SSH + X.509 cert engines, role table, KRL/CRL publishers, admin portal.  |
| `cert-agentd` | Per-workload credential agent. Renews SPIFFE X.509 + optional SSH user certs from `certd`.   |


## Status

**Production-shape, with the documented caveats.** `certd serve`
exposes the full HTTP API (SSH user / host / X.509 sign + revoke +
revocations + KRL spec), runs OIDC and mTLS caller auth, applies
role-table policy, publishes audit to NATS JetStream, and serves
the admin portal (roles CRUD, hosts list, sessions + asciinema
replay, audit tail, revocations). `cert-agentd run` renews the
workload X.509 cert at 60% TTL with KMS-style abstraction
support, optionally renews additional client certs for sibling
processes (`CERT_AGENTD_WORKLOADS_FILE` — per-cert SPIFFE URI, TTL,
and key type: ecdsa-p256 / ed25519), and optionally
renews an SSH user cert + writes an ssh_config drop-in.

Phase 7 hardening landed:
[THREAT_MODEL.md](THREAT_MODEL.md) (per-surface threats +
mitigations), [OPERATIONS.md](OPERATIONS.md) (deploy/scenario
runbooks), benchmark suite (`go test -bench=. -benchmem ./...`),
CSRF + HTTP Basic auth gates on the portal, and a remote-signer
abstraction operators wire KMS adapters against.

Operational caveats are tracked in [OPERATIONS.md §6](OPERATIONS.md):
in-memory role / mTLS-principal / revocation stores (no
hot-reload, no persistence yet), portal session ring caps at 200,
no per-org rate limiting at the API edge.


## Requirements

- Go 1.26.3+
- PostgreSQL 16+ (runtime + admin DSN)
- NATS JetStream (audit pipeline) — optional, gracefully degrades when absent
- AWS or GCP KMS (production CA key custody) — optional, in-memory signer for dev

## Build

```sh
make build         # → bin/certd + bin/cert-agentd + bin/auth-ssh-creds
make check         # gofmt + test + staticcheck + gopls + govulncheck
```

Benchmarks for the per-request hot paths (policy evaluation,
revocation lookup, signer round-trip):

```sh
go test -bench=. -benchmem -run=^$ ./internal/server/policy/...
go test -bench=. -benchmem -run=^$ ./internal/server/krl/...
go test -bench=. -benchmem -run=^$ ./internal/server/signer/...
```

### Docker images

Three images are published to GHCR on each tagged release
(multi-arch: linux/amd64 + linux/arm64):

| Image                                | Stage    | Ships                  | Use case                                                |
|--------------------------------------|----------|------------------------|---------------------------------------------------------|
| `ghcr.io/abagile/tokyo3-ca`          | `server` | `certd`                | Central CA service.                                     |
| `ghcr.io/abagile/tokyo3-ca-agent`    | `agent`  | `cert-agentd`          | Per-workload renewal agent on hosts that need certs.    |
| `ghcr.io/abagile/tokyo3-ca-cli`      | `cli`    | `auth-ssh-creds`       | CI runners / dev containers that prefer not to `go install`. |

Local builds via `make docker-build` (server), `make docker-build-agent`,
`make docker-build-cli`.

### Local dev rig (docker-compose)

`docker-compose.yml` stands up a self-contained certd ↔ cert-agentd
loop for end-to-end testing without external infrastructure:

```sh
make gen-certs                      # one-time: mkcert + openssl + ssh-keygen → ./shared/certs/
make docker-up                      # _sync-shared + compose up (auto-runs gen-certs if needed)
docker compose logs -f cert-agentd  # observe renewal cycle (~70 s with TTL=120 s)
curl https://localhost:8443/healthz # mkcert root in OS trust store — no --cacert needed
docker compose exec natsbox \
    nats stream view ca_audit       # tail the audit event stream
docker compose exec natsbox \
    nats stream view app_log        # tail certd + cert-agentd operational logs
make docker-down                    # stop (preserves volumes)
make clean-all                      # full reset (wipes shared/certs/* + named volumes)
```

**Layout.** Dev material lives under `./shared/` (mirrors the
tokyo3-auth tree so future expansion — postgres init scripts,
traefik configs, etc. — slots into the same shape):

```
shared/
  certs/
    gen.sh                # mkcert + openssl + ssh-keygen, host-side
    ca.crt                # mkcert root (host + container trust bundle)
    certd.{crt,key}       # certd HTTPS server cert
    cert-agentd.{crt,key} # bootstrap workload identity
    certd-signing.key     # CA signing key, PKCS#8 PEM (signs X.509 + SSH)
    certd-signing.key.pub # OpenSSH-format CA pubkey (TrustedUserCAKeys)
    certd-x509-ca.crt     # X.509 issuer cert → CERTD_CA_X509_CERT_FILE;
                          #   trust anchor for certd-issued mTLS leaves
  policy/                 # sample certd policy
    roles.json            # role table → CERTD_ROLES_FILE
    principals.json       # mTLS principal map (sample; prod mTLS path)
  agent/
    workloads.json        # extra cert-agentd workload certs → CERT_AGENTD_WORKLOADS_FILE
```

**Volume model.** `make docker-up` tar-pipes `./shared/` into a
docker-namespaced `ca_shared_data` named volume (compose's
auto-namespacing keeps it from colliding with sibling repos' own
`shared_data`). Every consumer mounts it read-only at `/shared`.
cert-agentd is the exception — it renews its own cert in place, so
the rig copies the bootstrap material onto a separate writeable
`agent_state` volume via the `cert-agentd-init` service on first
boot. That way, re-running `_sync-shared` never clobbers a renewed
cert.

**Policy & workloads (sample).** The rig enforces the
`shared/policy/roles.json` role table (`CERTD_ROLES_FILE`): the
`authd` group may obtain `spiffe://tokyo3/authd/*` certs (X.509 cap
`max_x509_cert_ttl_seconds: 86400`). cert-agentd authorises via
**body-groups** (`CERT_AGENTD_GROUPS=authd`, identity
`spiffe://tokyo3/authd/agent`) — the dev/test path, so no client-CA
bootstrap is needed. It provisions authd's four mTLS client certs from
`shared/agent/workloads.json` (`CERT_AGENTD_WORKLOADS_FILE`), all
Ed25519, into `/certs`: `db-app` (CN `auth_app`) and `db-admin` (CN
`auth_admin`) for Postgres cert-auth, plus `nats` and `scim`. Keys are
stable by default (cert-only rotation); set a workload's `rotate_key`
(or `CERT_AGENTD_ROTATE_KEY` for the agent's own cert) to regenerate the
key each renewal — leave it off for the Postgres certs, which can't
safely reload a rotating pair.
`shared/policy/principals.json` ships as a sample for the production
mTLS-principal path (`authd-agent` → `["authd"]`) but is left unwired —
that path needs verified client certs (`CERTD_API_CLIENT_CA` /
`CERTD_WORKLOAD_CA`), which the rig doesn't set. OIDC is also off;
production wires OIDC + mTLS principals on top.

**Three CAs, don't conflate them.** The rig has three public
trust artifacts, each for a different job:

- `ca.crt` — mkcert root. Verifies certd's **HTTPS server cert** and the agent's **bootstrap** cert (`CERT_AGENTD_WORKLOAD_CA`). This is the transport layer; it must stay mkcert.
- `certd-x509-ca.crt` — certd's **X.509 issuer cert** (`CERTD_CA_X509_CERT_FILE`). The anchor a workload pins to verify a *peer whose leaf certd issued* (the `authd-*` certs above). A real Postgres/NATS consumer would mount this, not `ca.crt`.
- `certd-signing.key.pub` — OpenSSH-format **SSH CA** pubkey (`TrustedUserCAKeys`). SSH world only; never goes in a TLS trust bundle.

Watch it work:

```sh
docker compose logs -f cert-agentd      # db-app + db-admin + nats + scim + self renewing
docker compose exec cert-agentd ls -l /certs   # authd-*.crt/key
docker compose exec natsbox nats stream view ca_audit  # x509.workload.cert.signed events
# Prove a provisioned leaf chains to the issuer cert (end-to-end trust):
docker compose exec cert-agentd sh -c \
  'openssl verify -CAfile /shared/certs/certd-x509-ca.crt /certs/authd-db-app.crt'
#   → /certs/authd-db-app.crt: OK
```

**Streams.** `natsbox` provisions two JetStream streams on boot:
`ca_audit` (compliance audit events, `ca.audit.events`; immutable,
long retention) and `app_log` (operational log shipping from certd +
cert-agentd via `tokyo3-base/applog`, capturing `app_log.>`; bounded
and deletable). `applog` publishes with core NATS, so without the
`app_log` stream those lines are silently dropped.

**Healthchecks.** certd (HTTPS `/healthz`) and cert-agentd
(filesystem mtime of the cert file, recent renewal proof). `natsbox`
is healthy once both streams exist, and stays running so you can
`docker compose exec natsbox sh` for the full `nats` CLI.

**Debugging (pprof).** Set `CERTD_DEBUG_ADDR` to expose
`net/http/pprof` on its own plaintext listener plus a 30s
goroutine/OS-thread stats log line — the dev rig enables it on `:6060`.
Use it to chase leaks (`pids.current` growth, goroutine counts):

```sh
curl http://localhost:6060/debug/pprof/goroutine?debug=1     # counts grouped by stack
curl http://localhost:6060/debug/pprof/threadcreate?debug=1  # OS threads ≈ pids.current
docker compose logs certd | grep 'runtime stats'            # goroutines/os_threads over time
```

Never set `CERTD_DEBUG_ADDR` on a deployed certd — pprof is
unauthenticated and rides its own listener, off the mTLS API.

See `shared/certs/gen.sh` for cert-generation details.

## Layout

```
cmd/
  certd/main.go              # central CA service entry point
  cert-agentd/main.go        # per-workload agent entry point
  auth-ssh-creds/main.go     # human-facing CLI: SSO → /api/v1/ssh/sign-user → SSH user cert
internal/
  server/                    # certd only
    api/                     # HTTP handlers (sign, role admin, recording ingest)
    portal/                  # admin web UI
    policy/                  # role table + sign-time enforcement
    signer/                  # InMemorySigner + KMSSigner
    sshengine/               # SSH cert builder + KRL publisher
    x509engine/              # X.509 / SPIFFE cert builder + CRL publisher
    krl/                     # revocation distribution
  agent/                     # cert-agentd only
    renew/                   # renewal scheduler
    output/                  # atomic file writers, ssh-config snippets
  client/                    # exported Go client for the certd HTTP API
  common/                    # lifecycle helpers shared by both binaries
```

## Design

- **One service, two cert engines.** certd internally separates SSH and X.509
  engines but ships as a single binary. Vault is **not** involved in CA key
  custody.
- **CA key custody**: in-memory signer for dev (file or env-injected key),
  remote signer for production. `signer.NewRemoteSigner` adapts a
  caller-supplied `RemoteSignFn` + cached public key into the
  `Signer` interface — operators wire concrete AWS KMS / GCP KMS /
  Vault Transit / HSM adapters at deployment without changing
  certd's core. The abstraction handles ctx-bounded remote calls
  (default 5s timeout) and surfaces remote errors verbatim wrapped
  with a `remote sign:` prefix; existing SSH cert + X.509 cert
  issuance paths work unchanged because the wrapper satisfies
  `crypto.Signer`.
- **Authorization**: the OIDC IdP issues tokens with a `groups` claim; certd's
  role table maps groups to allowed Unix principals + host patterns; the cert
  carries those as extensions; ssh-proxyd enforces what the cert says.
- **Lazy OIDC discovery.** certd's OIDC verifier defers issuer
  discovery + JWKS fetch to the first sign request, so certd boots
  even when the IdP is unreachable. A transient IdP outage at start
  surfaces as a 401 on the first sign request and self-heals on the
  next call once the IdP is up — no startup ordering required between
  the two daemons, no cyclic dependency.
- **Single agent** `cert-agentd` is the unified workload credential
  agent — one workload identity, multiple credential outputs (SPIFFE X.509 +
  optional SSH user cert).
- **Live-rotating mTLS cert.** `cert-agentd` wires its certd HTTP client
  through a `tls.Config.GetClientCertificate` reloader. After each
  successful renewal the renewer's `OnRenewed` hook refreshes the
  holder from disk, so the next mTLS handshake uses the fresh cert
  without restarting the binary. The bootstrap cert + key are
  provisioned externally (the agent never generates its X.509 key
  outside the renewer's `ensureKey` path).
- **ssh_config snippet (optional).** When `CERT_AGENTD_SSH_CONFIG_PATH`
  is set, the agent renders an Include-style `ssh_config` drop-in
  pointing at the cert-agentd-managed user cert/key with optional
  `ProxyJump` and `User`. The OpenSSH client re-reads the Include on
  every connection, so renewed user certs apply without SIGHUP.
- **Admin portal.** `certd` mounts a server-rendered HTML portal at
  `/portal/`. The scaffold ships a landing page that lists the planned
  pages (roles, hosts, sessions, audit) with their build status; later
  slices fill in each page. No client-side framework — pages render
  fully on the server and submit via standard form posts. The portal
  is optional: omitting `api.Config.Portal` leaves `/portal/*` routes
  unmounted (404). Per-page template sets keep page-specific
  `{{define "title"}}`/`{{define "body"}}` blocks from clobbering each
  other.
- **Cert revocation.** `POST /api/v1/ssh/revoke` records a cert as
  revoked by serial or KeyID (authenticated via the same OIDC/mTLS
  paths the sign endpoints use); the entry persists in
  `krl.InMemoryStore` until certd restarts. `GET /api/v1/ssh/revocations`
  returns the snapshot as JSON; ssh-proxyd polls it to populate its
  `IsRevoked` callback. `GET /api/v1/ssh/krl.spec` returns the same
  set in `ssh-keygen -k` KRL spec format — operators on non-proxy
  sshd boxes pipe it through `ssh-keygen -k -f /etc/ssh/revoked_keys
  -s ca.pub` to produce the binary KRL the `RevokedKeys` directive
  consumes. Revoke calls emit `ssh.cert.revoked` audit
  events so the portal audit tail surfaces them. Re-revoking an entry
  is idempotent and overwrites the Reason/Revoker annotation. The
  portal page at `/portal/revocations` lists the current set and
  exposes a form to revoke certs interactively (rendered Revoker
  field is `"portal"`).

- **Audit viewer (live, multi-stream).** `portal.AuditTracker`
  subscribes to N audit streams concurrently and normalizes each
  event into a common `AuditEvent` shape — both ssh-proxy's
  `audit.Entry` (user/target/client_ip/session_id) and certd's
  (caller/subject/ip) collapse onto the same actor/subject/ip
  columns, with the source labeled per row. `/portal/audit` renders
  newest-first across all sources (default cap 500). Denial events
  surface the policy reason inline; everything else shows the raw
  metadata blob in a collapsed `<details>` block.

- **Session list + replay.** Set `CERTD_SSH_AUDIT_URL` (or rely on the
  `CERTD_NATS_URL` fallback) and certd subscribes to ssh-proxyd's
  `ssh_audit` stream, decoding each `recording.completed` event into a
  bounded in-memory ring. `/portal/sessions` renders the recent
  sessions (newest first) with user, target, remote login, duration,
  and the cast file path; clicking a session ID opens
  `/portal/sessions/{id}` with an asciinema-player embed (loaded from
  the asciinema-player CDN) wired to `/portal/sessions/{id}/cast`.
  The replay endpoint streams the raw cast through a `LocalCastStore`
  rooted at `CERTD_CAST_DIR` — paths outside that root are refused
  with 403, sealing off the file-system attack surface a hostile
  `recording.completed` payload would otherwise open. The ring caps
  at `DefaultMaxSessions` (200); older sessions age out and have to
  be queried directly from JetStream.

- **Host registry viewer.** Set `CERTD_MTLS_PRINCIPALS_FILE` and the
  portal's `/portal/hosts` page lists every registered workload mTLS
  principal (SAN, name, group claims). Sorted by SAN for stable
  output across refreshes. Read-only: principal management lives in
  the JSON file (restart-to-reload) unless `CERTD_DATABASE_URL` is
  set, in which case the registry is persisted in the store (seeded
  once from the file).

- **Role table CRUD.** Set `CERTD_ROLES_FILE` to a JSON file of
  [`policy.Role`] objects and certd loads it as an in-memory
  policy store. The portal pages render the role list at
  `/portal/roles`, a detail view at `/portal/roles/{name}`, and the
  create/edit/delete forms at `/portal/roles/new` and
  `/portal/roles/{name}/edit|delete`. With the in-memory store, writes
  survive only until restart. Set `CERTD_DATABASE_URL` to use the
  **persistent store** instead — one backend behind the role table,
  the mTLS principal registry, *and* the SSH revocation list (KRL). A
  Postgres DSN selects the production backend (mirrors authd's
  `AUTH_DATABASE_URL`); `sqlite:<path>` (e.g.
  `sqlite:/var/lib/certd/certd.db`, or `sqlite::memory:`) selects the
  pure-Go SQLite backend for the dev rig. certd applies migrations on
  boot and CRUD writes survive restarts; `CERTD_ROLES_FILE` /
  `CERTD_MTLS_PRINCIPALS_FILE` then only seed a fresh database once.
  See `internal/store/`.

- **X.509 renewal anti-theft guard.** Active whenever the persistent
  store is configured: each workload-cert renewal must present its
  identity's *current* (or one-step-*previous*, the crash/rotation
  grace) serial via `current_serial`. A stale or unknown serial — a
  superseded or fabricated cert reappearing, i.e. a possible key-pair
  clone — is rejected `403` and emits a high-signal
  `x509.workload_cert.rollback_rejected` audit event. cert-agentd
  sends the serial of the cert on disk automatically (stateless across
  restarts). First issuance (no prior serial / no recorded state) is
  unguarded; resetting a locked-out identity means clearing its
  `active_workload_cert` row (re-enroll). Off entirely without a
  store. Refresh-token-rotation + reuse-detection, applied to certs —
  see `certd-store-design.md`.
  CSRF protection on every POST: each GET sets a `certd_csrf`
  cookie (256 bits of entropy, `SameSite=Lax`, `Secure` over HTTPS)
  and the rendered form embeds the matching value as a hidden
  input. POST handlers reject any submission whose cookie + field
  don't match (constant-time compare). An HTTP Basic auth gate
  (constant-time compared) activates when `CERTD_PORTAL_USERNAME`
  + `CERTD_PORTAL_PASSWORD` are both set; `/healthz` stays open so
  watchdogs don't need the credential. When the basic-auth pair is
  unset the portal is open and operators front it with oauth2-proxy
  or similar.

## CLI access via `auth-ssh-creds`

`auth-ssh-creds` is the human-facing client for certd's
`/api/v1/ssh/sign-user` endpoint. It runs an OIDC SSO dance against
an external IdP (typically tokyo3-auth), uses the resulting ID
token as the bearer for a single POST to certd, and writes the
signed cert + private key next to each other on disk so `ssh` can
pick them up via `-i`.

Lives in this repo (not the auth repo) because the wire shape it
tracks — certd's sign-user request/response — is owned here. SSO is
the prerequisite, not the API surface.

```sh
go install github.com/abagile/tokyo3-ca/cmd/auth-ssh-creds@latest
```

**One-time login** (re-uses the same OAuth public client you
registered for any other SSO-shaped CLI in your installation —
auth-aws-creds, future helpers, etc.):

```sh
auth-ssh-creds login --issuer https://id.example.com --client-id tokyo3-cli
# Browser flow on a loopback redirect; caches refresh + id tokens
# at ~/.config/auth-sso/{config,tokens}.json.
```

`--device` selects the RFC 8628 device authorization grant for
headless hosts (CI runners, container builds, jump boxes).

**On-demand cert minting**:

```sh
auth-ssh-creds get \
    --certd https://certd.internal \
    --principals alice,deployer \
    --ttl 1h
# auth-ssh-creds: cert written
#   key:  ~/.config/auth-sso/ssh-creds/keys/id_ed25519
#   cert: ~/.config/auth-sso/ssh-creds/keys/id_ed25519-cert.pub
#   ttl:  59m59s (valid_before 2026-05-27T15:00:00Z)
#   principals: alice,deployer
```

The first `get` generates an ed25519 keypair in
`~/.config/auth-sso/ssh-creds/keys/`; subsequent calls reuse it and
only refresh the signed certificate. `key_id` defaults to the `email`
claim in the ID token (falling back to `sub`); override with
`--key-id`. Pass `--groups eng,sre` when certd is configured with
`Policy` to enforce role-table membership.

**Drop-in `ssh_config` snippet** — pass `--proxy-jump
<ssh-proxyd-host:port>` and the helper prints a block you can
append to `~/.ssh/config` (or to a file `Include`d from it):

```sh
auth-ssh-creds get --certd ... --principals alice --proxy-jump bastion.internal:22 \
  | tee -a ~/.ssh/config.d/abagile
```

**Cache layout** under `${XDG_CONFIG_HOME:-~/.config}/auth-sso/`
(shared with every other `auth-*-creds` helper, so one `login`
serves all of them):

```
auth-sso/
├── config.json              ← issuer + client_id (non-secret, 0600)
├── tokens.json              ← OAuth access + refresh + id tokens (0600)
└── ssh-creds/
    └── keys/                ← ed25519 keypair + certd-signed cert (0600/0644)
```

The OIDC plumbing (browser flow, PKCE, token cache, refresh
rotation) lives in
[`github.com/abagile/tokyo3-base/auth/oidcclient`](https://github.com/abagile/tokyo3-base/tree/main/auth/oidcclient).
Only the SSH-specific bits (keypair generation,
`POST /api/v1/ssh/sign-user`, on-disk cert layout, ssh_config
snippet emission) live in
[`cmd/auth-ssh-creds`](cmd/auth-ssh-creds).

A containerized build is published as
`ghcr.io/abagile/tokyo3-ca-cli` for CI runners / dev containers
that prefer not to `go install`:

```sh
docker run --rm \
    -v "$HOME/.config/auth-sso:/root/.config/auth-sso" \
    -v "$HOME/.ssh:/root/.ssh" \
    ghcr.io/abagile/tokyo3-ca-cli \
    auth-ssh-creds get --certd https://certd.internal --principals alice \
        --key-out /root/.ssh/auth_ed25519 \
        --cert-out /root/.ssh/auth_ed25519-cert.pub
```

## Operational log shipping

Both binaries ship structured log lines to NATS (alongside stdout)
when their `*_NATS_URL` env var is set; unset leaves the logger at
stdout only. Subject layout depends on whether the daemon is a
cluster-wide singleton or runs on every workload host:

| Binary        | Subject                              | Env-var prefix    | `Instance` source                                       |
|---------------|--------------------------------------|-------------------|----------------------------------------------------------|
| `certd`       | `app_log.certd`                      | `CERTD_NATS_*`    | n/a — singleton                                          |
| `cert-agentd` | `app_log.cert-agentd.<instance>`     | `CERT_AGENTD_NATS_*` | `CERT_AGENTD_INSTANCE` (default `os.Hostname()`)      |

Operators can tail per-host with `nats sub 'app_log.cert-agentd.host-42'`
or fleet-wide with `nats sub 'app_log.cert-agentd.>'`. Every log
line on the per-host subject also carries a matching `"instance"`
slog attribute so attribute-based consumers can filter without
parsing subjects.

certd reuses its existing `CERTD_NATS_*` audit env vars (one
broker, two subjects). cert-agentd's NATS cert / key / CA each
fall back to the workload-identity material it already uses for
certd (`CERT_AGENTD_WORKLOAD_CERT/_KEY/_CA`) via the `WORKLOAD_*`
convention in `tokyo3-base/cli`, so a single TLS file set covers
both certd issuance and log shipping.

The shipper dials with `RetryOnFailedConnect(true)` and unbounded
reconnects — a broker that's down at boot doesn't fail process
startup; entries drop (200-entry discard-on-full buffer) while
disconnected and resume on reconnect. See the per-binary godoc in
[`cmd/certd/main.go`](cmd/certd/main.go) and
[`cmd/cert-agentd/main.go`](cmd/cert-agentd/main.go) for the
authoritative env-var reference.

## Operations

See [OPERATIONS.md](OPERATIONS.md) for deployment topology, the
initial-deploy checklist, scenario playbooks (rotate CA key,
revoke a cert, recover from NATS outage, diagnose replay errors),
cert-agentd lifecycle notes, and monitoring hooks.

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) for the per-surface threat
inventory + mitigations. Reviewers should walk the document's
checklist when auditing changes that touch the HTTP API, the
signer, audit emissions, or the portal.

## License

See [LICENSE](LICENSE).
