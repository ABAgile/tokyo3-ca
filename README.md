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
the admin portal (roles CRUD, hosts list, audit tail, revocations).
`cert-agentd run` renews the
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

Operational caveats are tracked in [OPERATIONS.md §7](OPERATIONS.md):
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
tokyo3-auth tree, so adding consumers like the Postgres rig below
slots into the same shape):

```
shared/
  certs/
    gen.sh                # mkcert + openssl + ssh-keygen + certd ca issue-{intermediate,server,workload}
    ca.crt                # mkcert root — anchors the traefik edge cert only
    traefik.{crt,key}     # traefik host-facing edge cert (mkcert-signed)
    certd.{crt,key}       # certd HTTPS API server cert (root-signed bootstrap leaf)
    certd-signing.key     # SSH CA signing key, PKCS#8 PEM (SSH certs only)
    certd-signing.key.pub # OpenSSH-format SSH CA pubkey (TrustedUserCAKeys)
    root.key              # two-tier ROOT key — signs the intermediate + bootstrap
                          #   leaves offline; certd serve never loads it
    certd-x509-ca.crt     # self-signed ROOT (pathlen:1) → CERTD_CA_ROOT_CERT_FILE;
                          #   the ONE anchor every consumer pins
    seal.key              # 32-byte AES key sealing the intermediate (DEV ONLY)
    certd-x509-int.crt    # intermediate issuer → CERTD_CA_X509_CERT_FILE
    certd-x509-int.key.sealed  # intermediate key, AES-sealed; unsealed at boot
    nats.{crt,key}        # NATS TLS server cert (root-signed bootstrap leaf)
    postgres.{crt,key}    # postgres TLS server cert (certd-issued)
    certd-nats.{crt,key}  # certd's NATS publisher client cert (certd-issued)
    certd-db.{crt,key}    # certd's Postgres client cert, CN=certd (certd-issued)
    natsbox.{crt,key}     # natsbox NATS client cert (certd-issued)
    cert-agentd.{crt,key} # cert-agentd bootstrap workload identity (certd-issued)
  policy/                 # sample certd policy
    roles.json            # role table → CERTD_ROLES_FILE (seeds the DB)
    principals.json       # mTLS principal map (sample; prod mTLS path)
  agent/
    workloads.json        # extra cert-agentd workload certs → CERT_AGENTD_WORKLOADS_FILE
  postgres/               # postgres mTLS rig (mounted at /shared/postgres)
    pg-entrypoint.sh      # stages server-key perms + enables ssl/HBA
    pg_hba_cert.conf      # mTLS-only HBA: hostssl cert, reject plain
    db-init.sh            # creates the auth_app/auth_admin login roles (CN → role)
  traefik/                # host-facing HTTPS edge (mounted at /shared/traefik)
    dynamic.yml           # file-provider: edge TLS termination + re-encrypt to certd
```

**Volume model.** `make docker-up` tar-pipes `./shared/` into a
docker-namespaced `ca_shared_data` named volume (compose's
auto-namespacing keeps it from colliding with sibling repos' own
`shared_data`). Every consumer mounts it read-only at `/shared`.
cert-agentd is the exception — it renews its own cert in place, so
the rig copies the bootstrap material onto a separate writeable
`agent_state` volume via the `cert-agentd-init` service on first
boot. That way, re-running `_sync-shared` never clobbers a renewed
cert. It's seeded as the SPIFFE **X.509-SVID layout** — `svid.pem` /
`svid.key` (from `cert-agentd.{crt,key}`) plus `svid_bundle.pem` (the
mTLS CA, from `certd-x509-ca.crt`) — the generic workload-credential
naming, so `/certs` reads as a standard SVID dir for the agent and the
sibling workloads it provisions. mkcert's `ca.crt` appears on no agent
path at all: the agent reaches certd **directly** (`certd:8443`, not via
traefik), and certd's listener cert is now certd-issued — so the agent
verifies even that hop against the internal CA
(`CERT_AGENTD_WORKLOAD_CA=/shared/certs/certd-x509-ca.crt`). The one
mkcert hop left is the traefik host-facing edge.

**Policy & workloads (sample).** The rig enforces the
`shared/policy/roles.json` role table (`CERTD_ROLES_FILE`, which now
*seeds* the Postgres store on first boot rather than feeding an
in-memory table): the `authd` group may obtain `spiffe://tokyo3/authd/*`
certs (X.509 cap `max_x509_cert_ttl_seconds: 86400`). cert-agentd
authorises via the **mTLS principal** path: `CERTD_API_CLIENT_CA`
verifies its client cert at the TLS layer, and
`shared/policy/principals.json` (`CERTD_MTLS_PRINCIPALS_FILE`) maps its
SAN `spiffe://tokyo3/authd/agent` → `["authd"]`. Both its bootstrap and
renewed certs carry that SAN, so it authenticates as the same principal
on the first request and every renewal — `CERT_AGENTD_GROUPS` is now an
inert fallback (body-groups aren't consulted once principals are wired).
It provisions authd's four mTLS client certs from
`shared/agent/workloads.json` (`CERT_AGENTD_WORKLOADS_FILE`), all
Ed25519, into `/certs`: `db-app` (CN `auth_app`) and `db-admin` (CN
`auth_admin`) for Postgres cert-auth, plus `nats` and `scim`. Keys are
stable by default (cert-only rotation); set a workload's `rotate_key`
(or `CERT_AGENTD_ROTATE_KEY` for the agent's own cert) to regenerate the
key each renewal — leave it off for the Postgres certs, which can't
safely reload a rotating pair. Both `roles.json` and `principals.json`
*seed* the Postgres store on first boot. OIDC stays off (no human
callers in the rig); production layers it on alongside the mTLS path.

**One root anchor, plus two edge anchors.** Every internal mTLS link
— certd ⇄ Postgres, certd ⇄ NATS, cert-agentd ⇄ NATS, and all provisioned
workload certs — verifies against a **single** anchor, `certd-x509-ca.crt`,
for both server and client certs. There is no per-channel CA and no bundle.
The rig runs certd's **two-tier hierarchy by default** (see the callout
below), so that one anchor is now the **root**:

- `certd-x509-ca.crt` — the self-signed **root** (pathlen:1), the ONE anchor consumers pin: NATS's `--tlscacert`, Postgres's `ssl_ca_file`, `CERTD_API_CLIENT_CA`, cert-agentd's bundle, and traefik's backend CA all point here. certd signs X.509 leaves with a sealed **intermediate** (`certd-x509-int.crt` = `CERTD_CA_X509_CERT_FILE`) that chains to this root, and presents leaves as leaf+intermediate; the nats/postgres *server* certs chain here too, so it works in both directions. `gen.sh` mints the root + intermediate offline, then issues the static bootstrap mesh certs (server/workload) directly under the root — the runtime certs certd issues (cert-agentd renewals, authd workloads) are intermediate-signed. Both validate to this same root, which is the only file any consumer references (the filename is unchanged from the old single-tier issuer, so nothing downstream moved).
- `ca.crt` — mkcert root. Anchors the **traefik host-facing edge cert** (`traefik.crt`) only. traefik publishes `:8443` to the host and terminates TLS with that mkcert cert (whose SANs cover `certd.localhost` — the portal vhost the router Host-matches — plus `localhost`/`127.0.0.1`, so both `curl https://localhost:8443` and the browser portal trust it with no `--cacert`), then re-encrypts to certd over the internal CA. mkcert no longer touches certd's own listener cert — that's certd-issued now and chains to `certd-x509-ca.crt` like every other mesh cert, so cert-agentd (which reaches certd directly, bypassing traefik) verifies it with the same single anchor. The mkcert root is *not* used for any internal link and stays out of cert-agentd's `/certs` volume. **Why edge-terminate only here:** certd's sign API is mTLS; terminating it at traefik would strip the caller's client cert and break SAN→principal auth, so machine traffic never transits the edge.
- `certd-signing.key.pub` — OpenSSH-format **SSH CA** pubkey (`TrustedUserCAKeys`). SSH world only; never goes in a TLS trust bundle.

> **Two-tier CA (rig default).** certd runs a two-tier X.509 hierarchy — an
> offline root (`root.key`, used only by `gen.sh`) signs a short-lived
> **intermediate** whose key is sealed; certd unseals it into memory at boot and
> signs leaves with it, so the root key never sits on the online issuance path.
> Consumers pin the **root** (`CERTD_CA_ROOT_CERT_FILE` = `certd-x509-ca.crt`)
> and each runtime leaf carries the intermediate in its chain. Wired via
> `CERTD_CA_SEALED_KEY_FILE` + `CERTD_CA_SEAL_KEY` + `CERTD_CA_ROOT_CERT_FILE`.
> **The seal is the one dev shortcut:** `CERTD_CA_SEAL_KEY=file:/shared/certs/seal.key`
> uses a local AES-256 key (certd logs a loud warning) instead of KMS — the key
> sits beside the ciphertext, so it's not real protection; production sets
> `CERTD_CA_SEAL_KEY` to a KMS key ref. SSH keeps its own signer
> (`certd-signing.key`) and gains a matching pollable CA-key set
> (`GET /api/v1/ssh/ca-keys`, `CERTD_SSH_CA_KEYS_FILE`). See
> [docs/two-tier-ca.md](docs/two-tier-ca.md) and OPERATIONS.md §3.

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

**Inbound API mTLS (by default).** certd's sign endpoints authenticate
the caller by its **verified client-cert SAN → principal** — body-groups
and OIDC are off. The cert must chain to `certd-x509-ca.crt`
(`CERTD_API_CLIENT_CA`) and its SAN must be a registered principal
(`CERTD_MTLS_PRINCIPALS_FILE`); a missing cert, an unverifiable cert, or
a verified cert whose SAN isn't a principal all yield `401`. cert-agentd's
steady renewals — the `x509.workload_cert.signed` events in the audit
stream above — *are* this path working end to end.

`/healthz` is the one exemption (`VerifyClientCertIfGiven`, so the
container healthcheck and host `curl` work without a client cert):

```sh
curl -s https://localhost:8443/healthz     # → 200 (ca_pubkey_hash, audit_active)
```

**Trust-bundle pull + hot-reload.** certd serves its current trust
anchor at `GET /api/v1/x509/trust-bundle` (`CERTD_CA_TRUST_BUNDLE`,
default = the issuer file; unauthenticated — CA certs are public). The
agent pulls it on a schedule when `CERT_AGENTD_TRUST_BUNDLE_PATH` is set
(the rig points it at `/certs/certd-x509-ca.crt`) and rewrites the
anchor atomically, so a CA rotation propagates without an out-of-band
push — the trust counterpart to leaf renewal. certd itself hot-reloads
`CERTD_API_CLIENT_CA` (per handshake) and a same-key `CERTD_CA_X509_CERT_FILE`
re-mint (per sign), keep-last-good on a bad drop-in; a new-key issuer is
refused live (restart after a signing-key rotation). See OPERATIONS.md §3
"Rotation note".

```sh
docker compose exec cert-agentd \
  wget -qO- --no-check-certificate https://certd:8443/api/v1/x509/trust-bundle
#   → {"trust_bundle":"-----BEGIN CERTIFICATE-----\n…"}
```

**Postgres (certd's store, mTLS by default).** certd uses the
`postgres` service as its persistent backend (`CERTD_DATABASE_URL`) —
the role table, mTLS principal registry, KRL, and the X.509
renewal/anti-theft guard all live here. There is **no plaintext path**:
`shared/postgres/pg_hba_cert.conf` rejects every non-TLS connection
(`host ... reject`) and requires each TLS client to present a
certificate whose CN matches the connecting role (`hostssl all all all
cert`). Roles map to client certs by CN — `certd` ← `certd-db.crt`
(certd itself, the owner/superuser), and `auth_app` ← `authd-db-app.crt`
/ `auth_admin` ← `authd-db-admin.crt` (the certs cert-agentd provisions,
demonstrating workload login). The service is **not** published to the
host — reach it via `docker compose exec postgres ...`.

Both directions use the one internal CA: postgres verifies connecting
**clients** against `certd-x509-ca.crt` (`POSTGRES_SSL_CA`), and its
**server** cert (`postgres.crt`) is certd-issued too, so clients verify
the server against the *same* anchor (`sslrootcert` in the DSN). The
`pg-entrypoint.sh` wrapper stages the server key with the perms+owner
postgres demands, then starts it with `ssl=on` and the cert HBA.

certd can present its client cert two ways. Embedding `sslcert`/`sslkey`
in `CERTD_DATABASE_URL` works but pins the cert at boot (pgx reads the
files once when it parses the DSN), so a cert-agentd rotation of
`certd-db.crt` isn't picked up until restart. Setting
`CERTD_DB_CERT`/`CERTD_DB_KEY`/`CERTD_DB_CA` instead routes the
connection through `tls/reloader`: the leaf is re-read per handshake and
the CA pool on mtime, so a rotated cert lands on the next pool dial
(within `SetConnMaxLifetime`) with no restart — matching how certd
already hot-reloads its serving and NATS certs. The DB **cert/key** are a
database-role credential and do **not** fall back to `CERTD_WORKLOAD_*`
(set them explicitly to enable mTLS to Postgres); only `CERTD_DB_CA`
falls back to `CERTD_WORKLOAD_CA`, the shared mesh trust root. Setting
`CERTD_DB_CA` without a client cert still enables server-auth TLS — the
Postgres server cert is verified against it (fail-secure), rather than
left to the DSN's `sslmode`.

Because the store is on, the **renewal/anti-theft guard** is active:
the first renewal of each provisioned identity is recorded as an
enrollment, and later renewals must present the current/previous serial
(the renewer reads it from the on-disk cert). A mismatch while the
recorded cert is still valid is treated as a possible clone and **locks
the identity** until an operator clears its row (it stays denied past
expiry — no auto-heal). A fresh DB has no rows, so the bootstrap
(self-issued) certs enroll cleanly — see OPERATIONS.md *Bootstrap a
workload with a self-issued mTLS cert* and *Recover a locked workload
identity*.

```sh
# A TLS connection without a client cert is refused — mTLS is mandatory:
docker compose exec postgres \
  psql 'host=postgres dbname=certd user=certd sslmode=require'
#   → FATAL: connection requires a valid client certificate

# certd's own client leaf authenticates as the certd role by CN:
docker compose exec postgres \
  openssl x509 -in /shared/certs/certd-db.crt -noout -subject
#   → subject=CN = certd
```

**NATS (mTLS by default).** The NATS client port runs `--tlsverify`,
so every publisher and consumer must present a client cert — there is
no plaintext NATS path. Unlike a typical split-anchor setup, **one CA
covers everything**: both the server cert (`nats.crt`) and every client
cert are certd-issued, so `--tlscacert`, each client's server-verify CA,
and the workload identities all resolve to `certd-x509-ca.crt`.

- certd's publisher cert (`certd-nats.crt`) and `natsbox`'s cert are
  self-issued offline by `gen.sh` (they connect at boot, before any
  runtime issuance exists), so they already chain to the CA.
- `cert-agentd` reuses its own workload cert as its NATS identity
  (`CERT_AGENTD_NATS_CERT` defaults to it). It's certd-issued from the
  bootstrap cert onward and stays certd-issued across renewals, so the
  single anchor never needs a second entry.

The monitoring port (`8222`) stays plaintext HTTP for the healthcheck.

```sh
# certd + cert-agentd ship logs and audit over mTLS; tail them via the
# TLS context natsbox saved on boot (no extra flags needed):
docker compose exec natsbox nats stream view ca_audit
# A plaintext client is refused at the handshake — mTLS is mandatory:
docker compose exec natsbox nats --server nats://nats:4222 stream ls
#   → nats: error: ... tls: first record does not look like a TLS handshake
```

**Streams.** `natsbox` provisions two JetStream streams on boot:
`ca_audit` (compliance audit events, `ca.audit.events`; immutable,
long retention) and `app_log` (operational log shipping from certd +
cert-agentd via `tokyo3-base/applog`, capturing `app_log.>`; bounded
and deletable). `applog` publishes with core NATS, so without the
`app_log` stream those lines are silently dropped.

**Healthchecks.** certd (HTTPS `/healthz`) and cert-agentd
(filesystem mtime of the cert file, recent renewal proof). `traefik`
(the host-facing HTTPS edge) is healthy once its `/ping` entrypoint
answers, and waits on certd being healthy first. `natsbox` is healthy
once both streams exist, and stays running so you can `docker compose
exec natsbox sh` for the full `nats` CLI.

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

**Rate limiting.** Set `CERTD_RATE_LIMIT_RPS` (with optional
`CERTD_RATE_LIMIT_BURST`) to cap requests per source IP via an
in-process token bucket — defense-in-depth that shields the auth path
and CA signer from a single-source flood. It is disabled by default,
per-replica (not distributed), and exempts `/healthz`; an edge LB/WAF
remains the answer for volumetric/distributed DoS. Keying is on the
peer IP — set `CERTD_TRUSTED_PROXIES` to a CIDR list to instead trust
`X-Forwarded-For` from those proxies.

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
  other. In the docker rig it's reachable through the traefik edge at
  **`https://certd.localhost:8443/portal/`** and gated by the HTTP Basic
  credentials (`CERTD_PORTAL_USERNAME`/`CERTD_PORTAL_PASSWORD`, default
  `admin` / `certd-dev` — override via the host env). OIDC needs a real
  IdP, so the rig uses the Basic gate; setting only one of the two creds
  leaves the portal unguarded.
- **Native OIDC portal login.** When the `CERTD_PORTAL_OIDC_*` env is
  set, the portal runs a browser Authorization-Code + PKCE flow against
  the IdP (`/portal/auth/login` → `/authorize` → `/portal/auth/callback`),
  verifies the ID token (signature + `nonce`), and seals an encrypted
  session cookie (AES-256-GCM via `base/crypto`, `CERTD_PORTAL_SESSION_KEY`).
  Access requires a valid session and membership in `CERTD_PORTAL_ADMIN_GROUP`
  (default `ca-portal-admin`, minted as a SCIM group in the IdP). Reuses
  `base/auth/oidcclient` for the token exchange and certd's own OIDC verifier
  (a second instance keyed to the portal's `client_id`). Supersedes the HTTP
  Basic gate; mutations are attributed to the signed-in user's email.
- **Config reconciliation (GitOps).** `certd reconcile` diffs
  `CERTD_ROLES_FILE` / `CERTD_MTLS_PRINCIPALS_FILE` against the database and
  applies the difference, so file edits take effect after the seed-on-first-
  boot. An owner-marker `source` column makes config authoritative over the
  rows it owns (add / update / **prune** to match the files) while portal-
  created rows (`source=portal`) are never pruned; a collision is a conflict,
  skipped unless `--adopt` takes ownership. Dry-run by default; `--apply`
  writes. Run it out-of-band from CD — no server endpoint, no extra auth.
- **Owner-marker on policy rows.** Roles and principals carry a `source`
  column — `config` (managed by `certd reconcile`) or `portal` (created in the
  admin portal) — so reconcile can prune the config-owned set without touching
  portal-created rows. Mutations (portal + reconcile) are recorded in the
  structured log, attributed to the acting user (`oidc:<email>` /
  `portal:<user>` / `config:<actor>`); the log ships to NATS via applog when
  configured.
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

- **Audit viewer (live).** `portal.AuditTracker` tails certd's own
  `ca_audit` stream into a bounded ring (`caller`/`subject`/`ip` per
  event). `/portal/audit` renders newest-first (default cap 500); each
  row's metadata blob expands in a collapsed `<details>` block.

- **SSH session + access views live in ssh-proxyd, not here.** The
  recorded-session list, asciinema replay, **and** the SSH-access audit
  viewer are all served by ssh-proxyd's own portal (it produces the
  recordings and owns the `ssh_audit` stream). certd's `/portal/audit`
  shows only certd's own cert-lifecycle events — it no longer subscribes
  to ssh-proxyd's stream.

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
  grace) serial via `current_serial`. A stale or unknown serial **while
  the recorded cert is still valid** — a superseded or fabricated cert
  reappearing, i.e. a possible key-pair clone — **locks the identity**:
  `403`, `locked_at` + the offending serial stamped on its row, and every
  later sign request denied (past expiry too — no auto-heal), emitting a
  high-signal `x509.workload_cert.locked` event. cert-agentd sends the
  serial of the cert on disk automatically (stateless across restarts).
  First issuance (no recorded state) is unguarded. **Lost-cert recovery
  (not a clone):** if the recorded cert has *expired* and the identity is
  **not** locked, a renewal that can't present a matching serial (e.g. an
  agent that lost its cert) re-enrolls — no valid credential is in the
  wild, so the guard is moot (caller auth + role policy still apply) —
  emitting `x509.workload_cert.reenroll`; it auto-heals within one cert
  TTL. A **locked** identity does *not* auto-heal — an operator clears its
  `active_workload_cert` row to reset (OPERATIONS.md *Recover a locked
  workload identity*). **Adoption ack:** once cert-agentd has durably
  persisted a renewed cert it calls `POST /api/v1/x509/adopt` with the new
  serial, and certd collapses the grace (drops `previous`) — shrinking the
  window the rotated-from serial stays acceptable from "until the next
  renewal" to "until the ack" (best-effort; a missed ack just leaves the
  one-step grace). Off entirely without a store. Refresh-token-rotation
  + reuse-detection, applied to certs — see `certd-store-design.md`.
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
