# tokyo3-ca operations runbook

Day-to-day operational guidance for running `certd` and
`cert-agentd` in production. Use alongside the per-binary godoc in
`cmd/*/main.go` (the authoritative env-var reference) and
[THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Deployment topology

```
                                         ┌────────────────┐
            ┌──────────────────────► OIDC IdP (authd)      │
            │      ID tokens          └────────────────┘
            │
┌───────────┴───────────┐                ┌────────────────┐
│       certd (this)    │◄───────────────┤  NATS JetStream │
│  HTTPS  :8443         │  audit publish └────────────────┘
│  mTLS + OIDC auth     │
└──────────┬────────────┘
           │
   workload mTLS sign-user / sign-host / sign-workload / revoke
           │
   ┌───────┴────────┐      ┌─────────────────┐
   │ ssh-proxyd     │      │ cert-agentd     │   (per workload)
   │ ssh-tunneld    │      │  - renews X.509 │
   │ (other         │      │  - renews SSH   │
   │  workloads)    │      │    user cert    │
   └────────────────┘      └─────────────────┘
```

Single-region deployment: one `certd` process behind a load balancer
or directly on an internal hostname; one `cert-agentd` per workload
host that needs renewable credentials.

## 2. Initial deploy checklist

1. **Generate or import the CA key.**
   - Dev: `openssl genpkey -algorithm ed25519 -out ca.key`; `CERTD_CA_KEY_FILE=ca.key`.
   - Prod: provision an asymmetric SIGN_VERIFY key in your KMS (AWS KMS, GCP KMS, Vault Transit, or HSM); wire it via a `signer.NewRemoteSigner` adapter in your deployment glue.
2. **Configure mTLS for the API.**
   - `CERTD_API_CERT` + `CERTD_API_KEY` = the server certificate the workloads validate.
   - `CERTD_API_CLIENT_CA` = the CA bundle workload certs are signed by.
3. **Provision OIDC verification** (humans-and-OIDC path) via `CERTD_OIDC_ISSUER` + matching JWKS reachability.
4. **Seed the role table.** Write `CERTD_ROLES_FILE` as a JSON array of `policy.Role` objects (see `internal/server/policy/policy.go` for the struct shape).
5. **Seed the workload registry.** Write `CERTD_MTLS_PRINCIPALS_FILE` as a JSON array of `mtls.Principal` (Name, SAN, Groups).
6. **Hook NATS** for audit publish: `CERTD_NATS_URL` + the per-stream TLS env vars. Without it the audit stream is a no-op (dev only).
7. **Subscribe to ssh-proxy's audit stream** for the portal session list: `CERTD_SSH_AUDIT_URL` (falls back to `CERTD_NATS_URL`).
8. **Point the cast root at the same mount** ssh-proxy writes to: `CERTD_CAST_DIR`. Without this the portal session-detail page can't replay.
9. **Set portal credentials.** `CERTD_PORTAL_USERNAME` + `CERTD_PORTAL_PASSWORD` if no upstream identity-aware proxy is in front; otherwise leave both empty and trust the edge.

Start the binary, hit `https://certd/healthz` to confirm it bound,
and follow with `/portal/` to confirm the auth gate behaves as
expected.

## 3. Common scenarios

### Rotate the CA key

The cert-issuance public key is what every workload validates. To
rotate without downtime:

1. Provision the new KMS key (or generate the new in-memory key).
2. Issue a "rollover" cert from the new CA signed by both old and
   new keys — not yet supported in code; deploy plan is to:
   - Stand up `certd-new` on a different port with the new
     signer.
   - Run both in parallel, advertising both CA public keys
     downstream.
   - Once every consumer has the new pubkey in its trust bundle,
     decommission the old `certd`.
3. Until a true rollover is wired, treat this as a planned-outage
   operation: cut over consumers atomically.

### Add a new tunnel host

1. Issue the workload an mTLS cert with a SPIFFE URI of the form
   `spiffe://<trust-domain>/host/<fqdn>`. `cert-agentd` on that
   host can renew the cert thereafter, but the **initial** cert is
   operator-bootstrapped (Kubernetes secret, manual install, etc.).
2. Register the workload identity in `CERTD_MTLS_PRINCIPALS_FILE`:
   `{"name":"db-1.prod","san":"spiffe://td/host/db-1.prod","groups":["ssh-tunnel-host"]}`.
   Reload certd (no hot-reload yet — schedule a restart).
3. Add a role in `CERTD_ROLES_FILE` that grants the new group
   permission to sign host certs (or reuse an existing
   `ssh-tunnel-host` role).
4. The workload's `ssh-tunneld` picks up the trust-bundle and
   starts renewing on the next cycle.

### Revoke a cert (immediate)

Three equivalent paths:

- **API:** `curl -u admin:secret https://certd/api/v1/ssh/revoke -d '{"serial":42,"reason":"compromised"}'`.
- **Portal:** Sign in → `/revocations` → fill the form.
- **Bulk** (initial seeding): no current bulk-import endpoint;
  POST in a loop.

After revocation:
- ssh-proxyd picks it up at the next `CERTD_REVOCATIONS_POLL_SECONDS`
  cycle (default 30s) and refuses the cert at the next handshake.
- Non-proxy sshd hosts: `curl https://certd/api/v1/ssh/krl.spec | ssh-keygen -k -f /etc/ssh/revoked_keys -s ca.pub -` and reload sshd.

### Recover from a NATS outage

certd's audit publish is best-effort — when NATS is unreachable,
sign endpoints still succeed and the events are logged at warn
level. After recovery:

1. Confirm `CERTD_NATS_URL` is reachable from the certd host.
2. Restart certd (the audit sink reconnects lazily; restart is the
   simple knob).
3. Cross-check the portal `/audit` page tail for the gap window.
   Events emitted during the outage are **lost** — there is no
   replay buffer. Operators should alert on broker unavailability.

### Increase audit retention

The audit stream is configured at the broker side: `nats stream
edit ca_audit --max-age 1y` (or whatever your retention SLO is).
certd's `StreamMaxAge` constant only governs the bootstrap config;
operator changes after first run live in the broker.

### Diagnose "/portal/sessions can't replay"

Common causes, in order of likelihood:

1. **`CERTD_CAST_DIR` not configured** — page shows "cast store is not configured". Set the env var to the same path ssh-proxy writes to.
2. **Cast root mismatch** — the proxy writes to `/var/lib/ssh-proxyd/casts` but certd reads from a different mount. `/portal/sessions/{id}/cast` returns 403. Align the paths.
3. **No PTY** — the session ran without `pty-req` (typical for `scp` or non-interactive `ssh user@host command`). No cast file exists; UI says "session was not PTY-recorded".
4. **Stale session out of ring** — the in-memory session tracker caps at 200; older sessions return 404. Query the `ssh_audit` JetStream stream directly for older records.

## 4. cert-agentd operational notes

### First-run bootstrap

`cert-agentd` needs a workload mTLS cert + key at startup to talk
to certd. The renewer takes over from there:

- The X.509 key stays stable across renewals (only the cert
  rotates). Don't delete the key file between renewals.
- The SSH user key (when wired) is generated on first run if absent
  at `CERT_AGENTD_SSH_USER_KEY`.
- The ssh-config snippet at `CERT_AGENTD_SSH_CONFIG_PATH` is
  written once at startup; the OpenSSH client re-reads it on every
  connection.

### What happens when certd is unreachable

The renewer logs at warn and schedules a retry per
`renew.DefaultRetryBackoff` (30s, fixed interval — not exponential).
The previously-issued cert keeps serving until expiry. Operators
should alert when `cert-agentd`'s structured logs surface "sign
workload cert" errors for more than ~60% of the cert's TTL.

Each retry-log line carries `mtls_cert_remaining=<duration>` — the
time left on the mTLS material the agent currently presents to certd.
When this number drops to zero before a renewal succeeds, every
subsequent retry fails at the TLS handshake itself and the agent
can no longer recover without operator intervention (replace the
on-disk cert+key manually, then restart). Alert thresholds should
fire well before `mtls_cert_remaining` reaches zero.

At startup, if the loaded mTLS cert is within 24h of expiry, the
agent emits a one-shot warn:
`bootstrap mTLS cert near expiry — first renewal must succeed before it dies`.
This is the earliest signal that a long certd outage could leave
the agent unable to recover.

### When to restart cert-agentd

- Configuration changes (env vars) — restart.
- KMS / certd endpoint change — restart.
- Workload cert revoked: the existing cert keeps validating
  upstream until it expires OR the next renewal fails (revoked
  cert can't authenticate to certd to refresh). Restart isn't
  needed but won't hurt.

## 5. Monitoring hooks

| Probe                                  | What it confirms                                           |
|----------------------------------------|------------------------------------------------------------|
| `GET https://certd/healthz`            | certd HTTP server is up + reports CA pubkey hash           |
| `GET https://certd/portal/healthz`     | Portal mux is up (exempt from Basic auth)                  |
| NATS subject `ca.audit.events`         | Tail for every issued / denied / revoked cert              |
| NATS subject `ssh.audit.events`        | Tail for every SSH session lifecycle event                 |
| certd structured logs                  | INFO on every successful sign; WARN on audit failures      |
| cert-agentd structured logs            | INFO on each renewal; WARN on certd-unreachable bursts     |
| Portal `/audit` page                   | Combined view of certd + ssh-proxy events                  |

## 6. Known limitations

- **No bulk-import endpoint** for the revocation set. Use the
  `POST /api/v1/ssh/revoke` endpoint in a loop.
- **No hot-reload** for `CERTD_ROLES_FILE` / `CERTD_MTLS_PRINCIPALS_FILE`.
  Restart certd to pick up changes.
- **In-memory revocation store** — restart clears it; back via
  audit-log replay or a future persistent backend.
- **Portal session list caps at 200** — older sessions need
  JetStream tail.
- **No per-org rate limiting** at the API. Front certd with a
  rate-limiting edge if needed.
