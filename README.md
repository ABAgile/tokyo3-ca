# tokyo3-ca

Certificate authority for internal platform. Issues short-lived SSH
certificates (user / host / per-session) and X.509 / SPIFFE workload identity
certificates against an OIDC-group-driven role table. Integrates with the
existing `authd` (OIDC IdP) and `vaultd` (secret store + envelope crypto)
services under the same application suite platform.

This repo ships two binaries:

| Binary        | Role                                                                                         |
|---------------|----------------------------------------------------------------------------------------------|
| `certd`       | Central CA service. SSH + X.509 cert engines, role table, KRL/CRL publishers, admin portal.  |
| `cert-agentd` | Per-workload credential agent. Renews SPIFFE X.509 + optional SSH user certs from `certd`.   |


## Requirements

- Go 1.26.3+
- PostgreSQL 16+ (runtime + admin DSN)
- NATS JetStream (audit pipeline) — optional, gracefully degrades when absent
- AWS or GCP KMS (production CA key custody) — optional, in-memory signer for dev

## Build

```sh
make build         # → bin/certd + bin/cert-agentd
make check         # gofmt + test + staticcheck + gopls + govulncheck
```

## Layout

```
cmd/
  certd/main.go              # central CA service entry point
  cert-agentd/main.go        # per-workload agent entry point
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
  KMS-backed signer for production.
- **Authorization**: `authd` issues OIDC tokens with a `groups` claim; certd's
  role table maps groups to allowed Unix principals + host patterns; the cert
  carries those as extensions; ssh-proxyd enforces what the cert says.
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
- **Role table CRUD.** Set `CERTD_ROLES_FILE` to a JSON file of
  [`policy.Role`] objects and certd loads it as an in-memory
  policy store. The portal pages render the role list at
  `/portal/roles`, a detail view at `/portal/roles/{name}`, and the
  create/edit/delete forms at `/portal/roles/new` and
  `/portal/roles/{name}/edit|delete`. Writes mutate the in-memory
  store and survive only until restart unless externally persisted.
  **The CRUD-write routes have no CSRF protection yet** — mounting
  the portal unauthenticated exposes the role table to cross-site
  forgery. Production deployments need to gate `/portal/*` behind
  OIDC + session-bound CSRF tokens before enabling writes.

## License

See [LICENSE](LICENSE).
