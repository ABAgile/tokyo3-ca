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

## License

See [LICENSE](LICENSE).
