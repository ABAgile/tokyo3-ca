# tokyo3-ca threat model

This document captures the trust boundaries, attack surfaces, and
mitigations for `certd` and `cert-agentd`. It exists so a reviewer
can audit each mitigation against the corresponding source rather
than re-deriving it from code comments.

Scope: code in this repository. Out of scope: the workloads that
consume certs (`tokyo3-ssh-proxy` has its own threat model), the
NATS broker, the IdP, and the operator's secret-management pipeline.

## Components and trust boundaries

```
            ┌──────────────────────────────────────────────┐
            │             certd (this repo)                │
            │                                              │
  OIDC/mTLS │  ┌────────────┐    ┌───────────────────┐     │
 ──────────►│  │  HTTP API  │───►│ policy.Engine     │     │
            │  └─────┬──────┘    └──────┬────────────┘     │
            │        │                  │                  │
            │        ▼                  ▼                  │
            │  ┌────────────┐    ┌───────────────────┐     │
            │  │  signer.   │    │ x509engine        │     │
            │  │  Signer    │    │ sshengine         │     │
            │  └─────┬──────┘    └─────────┬─────────┘     │
            │        │                     │               │
            │   (KMS / file)               ▼               │
            │        │              ┌──────────────┐       │
            │        ▼              │ audit.Sink   │──► NATS
            │  KMS / disk           └──────────────┘       │
            │                                              │
            └──────────────────────────────────────────────┘
                                ▲
                                │ portal + revocations
                                │
                       ┌────────────────┐
                       │ Admin browser  │
                       └────────────────┘
```

Trust boundaries (each labelled edge crosses one):

| Boundary               | Direction              | Mechanism                                 |
|------------------------|------------------------|-------------------------------------------|
| Caller → API           | Inbound HTTPS          | OIDC bearer token OR mTLS client cert     |
| Admin → Portal         | Inbound HTTPS          | HTTP Basic auth + CSRF tokens             |
| API → policy.Engine    | In-process call        | none (trusted)                            |
| API → signer.Signer    | In-process / KMS API   | KMS auth (per-deployment)                 |
| API → audit.Sink       | NATS publish           | mTLS to broker                            |
| Operator → role file   | Filesystem             | filesystem ACL                            |

## Surfaces and threats

### S1. HTTP API at `:8443`
**Surface:** `/api/v1/ssh/*`, `/api/v1/x509/*`, `/api/v1/ssh/revoke`,
`/api/v1/ssh/revocations`, `/api/v1/ssh/krl.spec`, `/healthz`,
`/portal/*`.

Threats:

| # | Threat                                                                              | Mitigation                                                                                                                                                                                                                  |
|---|-------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Anonymous caller obtains a cert                                                     | `Server.authenticate` (`internal/server/api/server.go`) requires OIDC token OR verified mTLS principal. Body-groups fallback only when neither verifier is configured; production wires both.                              |
| 2 | Authenticated caller obtains a cert outside their role                              | `policy.Engine.EvaluateUserCert` / `EvaluateHostCert` / `EvaluateX509Cert` filter requested principals against the caller's groups + role-table allowances. Denials emit `*.denied` audit events.                          |
| 3 | TTL elevation                                                                       | `resolveTTL` (`sign_ssh.go`, `sign_x509.go`) caps the requested TTL at the per-endpoint maximum AND the per-role max (whichever is lower).                                                                                  |
| 4 | Replay / token theft                                                                | OIDC tokens are short-lived and the verifier rejects replays by audience + nonce. mTLS rejects revoked workload identities via the in-flight CRL the operator wires (out of scope for this repo).                          |
| 5 | Mass cert minting (DoS or stockpiling)                                              | Opt-in per-source-IP rate limiting at the API layer (`CERTD_RATE_LIMIT_RPS`, token bucket keyed on the peer IP — `X-Forwarded-For` honored only for `CERTD_TRUSTED_PROXIES`). In-process and per-replica — defense-in-depth that shields the auth path + CA signer from a single-source flood, NOT a substitute for an edge LB/WAF against volumetric/distributed DoS. Disabled by default. |
| 6 | Cross-site forgery against the portal                                               | `validateCSRF` (`portal/csrf.go`) enforces double-submit-cookie on every POST. SameSite=Lax + constant-time compare. Tests in `csrf_test.go`.                                                                              |
| 7 | Cross-tenant access via portal                                                      | Optional HTTP Basic gate (`portal/auth.go`); operators front the portal with an identity-aware edge (oauth2-proxy, OIDC) in multi-user deployments. Single-admin Basic auth is the documented default.                     |
| 8 | Revocation set disclosure to attackers                                              | Both `/api/v1/ssh/revocations` and `/api/v1/ssh/krl.spec` go through `Server.authenticate`. Residual: a compromised caller can scrape the set — accepted because the revocation list isn't itself a secret.                |
| 9 | Audit log loss masking a breach                                                     | `audit.Append` failures are logged at warn but do not block the request. Residual: if NATS is down + an attacker exploits a sign endpoint, the event is lost. Operators must alert on broker unavailability.               |
| 10 | Stolen workload key pair re-used to mint fresh certs (clone)                       | The X.509 renewal/anti-theft guard (`sign_x509.go` + `active_workload_cert`) binds each identity to its `{current, one-step-previous}` serial. A serial outside that window while the recorded cert is still valid is a possible clone: the identity is LOCKED (`locked_at` + `locked_serial`, `x509.workload_cert.locked`) and denied on every later request — past expiry too — until an operator clears the row (`DELETE`). The one-step grace tolerates a crash mid-rotation; an *unlocked* expired identity auto-re-enrolls (`x509.workload_cert.reenroll`). An adoption ack (`POST /api/v1/x509/adopt`, sent by the agent once a new cert is durably persisted) collapses that grace early — shrinking the rotated-from acceptance window from one renewal interval to one ack round-trip. Off without a persistent store. Residuals: an out-of-band serial can false-lock a healthy agent (manual clear, no API/portal control yet); a stolen cert presented within its one-cycle `current` window is still accepted until the next mint supersedes it. |

### S2. signer.Signer (CA key custody)
**Surface:** the CA private key.

Threats:

| # | Threat                                                  | Mitigation                                                                                                                                                                                            |
|---|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | CA key disclosure                                       | Production uses `signer.NewRemoteSigner` against KMS/HSM (`signer/remote.go`); the key never enters the certd process. In-memory signer is documented as dev-only — its description string is logged. |
| 2 | CA key compromise via process memory dump (in-memory)   | Accepted residual risk in dev. Mitigation in prod is `RemoteSigner`. The plan calls for `mlock`-style protection on the in-memory path — NOT IMPLEMENTED; tracked as future work.                     |
| 3 | KMS impersonation via stolen IAM credentials            | Out of scope — KMS auth is the operator's IAM responsibility. RemoteSigner's `Description` field surfaces the configured key ARN in audit + portal for forensic comparison.                            |
| 4 | Timing side channel on Sign                             | `RemoteSigner.Sign` runs under a configurable timeout; the remote service handles constant-time signing.                                                                                              |

### S3. Audit publish
**Surface:** NATS JetStream stream `ca_audit` with subject
`ca.audit.events`. The portal /audit page reads from it.

Threats:

| # | Threat                                                | Mitigation                                                                                                                                              |
|---|-------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Forged audit entries                                  | Each `Entry` is `journal.NewJSONSink[audit.Entry]`-published over mTLS to the broker — the workload identity authenticates the publisher. Brokers must reject unauthenticated publishes (operator config). |
| 2 | Audit entry tampering at rest                         | JetStream retention is append-only; the broker enforces it. Out of scope for certd code.                                                                |
| 3 | Audit metadata leakage                                | `Entry.Metadata` is operator-supplied JSON; the audit-helper in `emitAudit` (`sign_ssh.go`) never embeds raw credential material. Reason fields are operator-curated.                                       |

### S4. Revocation propagation
**Surface:** `krl.InMemoryStore`, `GET /api/v1/ssh/revocations`,
`GET /api/v1/ssh/krl.spec`.

Threats:

| # | Threat                                          | Mitigation                                                                                                                                                                                                       |
|---|-------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Revocation forgery (admin → "revoke alice")     | All `POST /api/v1/ssh/revoke` calls go through `authenticate`; the audit event records the revoker. Portal-form revocations are tagged `revoker: portal` so the audit caller is the authenticated Basic user.   |
| 2 | Replay-attack via stale snapshot                | `Snapshot.CapturedAt` is included; consumers can detect staleness. ssh-proxyd's `revcheck.PollingChecker.Healthy()` surfaces `lastFetchErr` for monitoring.                                                       |
| 3 | Revocation set lost on restart                  | `InMemoryStore` is non-persistent. Mitigation: the audit log contains every revocation; operators replay it OR back the store with Postgres (future slice). Documented as residual risk.                          |

### S5. Portal auth + session
**Surface:** browser ↔ portal HTTP.

Threats:

| # | Threat                                          | Mitigation                                                                                                                                                                                        |
|---|-------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Brute force on Basic-auth                       | Constant-time compare (`auth.go`). The opt-in per-source-IP API limiter (`CERTD_RATE_LIMIT_RPS`) also covers `/portal/*` and bounds attempt throughput per IP; still front with an edge that rate-limits 401s for distributed attempts.                          |
| 2 | Session hijack via cookie theft                 | CSRF cookie is `SameSite=Lax` + `Secure` over HTTPS. There is no portal SESSION cookie (the Basic-auth header is sent on each request).                                                            |
| 3 | XSS in rendered HTML                            | All template fields go through `html/template` auto-escaping. Operator-supplied annotations (Reason, Revoker) escape automatically.                                                                |

## Residual risks (known + tracked)

1. **API rate limiting is opt-in and per-replica** — `CERTD_RATE_LIMIT_RPS` enables an in-process per-source-IP token bucket (default off); it shields a single instance but is not distributed, so volumetric/distributed DoS still leans on the operator's edge (LB/WAF).
2. **In-memory revocation store (default)** — non-persistent; a Postgres/SQLite backend is available opt-in via `CERTD_DATABASE_URL` (`internal/store`), so revocations survive restart when configured.
3. **No periodic KMS-key liveness probe** — the bundled KMS path fetches the CA public key at startup (a missing or inaccessible key fails boot, not the first sign), but there is no recurring re-check of continued accessibility while running.
4. **Portal Basic auth is single-tenant** — multi-user RBAC for the portal needs OIDC integration (out of scope for v1).
5. **The audit-log loss-tolerance is deliberate** but is a residual risk if the broker is offline during a malicious sign attempt.

## Out-of-scope assumptions

- `tokyo3-base/tls` produces correct TLS configurations from the
  configured PEM files. Trusted.
- The operator's OIDC IdP issues tokens that honour the `groups`
  claim. Trusted; certd verifies the signature but not the IdP's
  internal flows.
- NATS JetStream's append-only retention is configured correctly by
  the operator. Trusted.
- The KMS / HSM the operator configures for `RemoteSigner` enforces
  its own access control. Trusted.

## Review checklist

When reviewing certd changes, walk through:

1. Does the change introduce a new HTTP route? Check `Server.authenticate` runs first.
2. Does it consume operator input (env var, JSON file, request body)? Confirm validation + bounds checking.
3. Does it touch the signer interface? Confirm the public key isn't required to be `crypto.PublicKey == nil`; cache hygiene under concurrent calls.
4. Does it touch the portal? CSRF on POSTs; HTML escaping in templates; auth gate not bypassable.
5. Does it modify audit emissions? Confirm `Entry.Caller` is populated and the action name is added to `audit/audit.go`'s `Action*` constants.
