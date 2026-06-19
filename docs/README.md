# tokyo3-ca documentation

The docs map. The top-level [`../README.md`](../README.md) is the front
door — *what the repo is and does*; this folder holds the deeper material.
Each doc owns one purpose; nothing here restates another (see the
canonical-sources table below — that's the anti-drift rule).

## Read this when…

| Doc | Purpose | Reach for it when… |
|---|---|---|
| [architecture.md](architecture.md) | **As-built** key/cert hierarchy + trust topology | "How does the trust fit together? What signs what, who anchors what?" — start here to understand the system |
| [two-tier-ca.md](two-tier-ca.md) | **Design rationale** for the two-tier CA (ADR-style) | "Why two-tier? What were the trade-offs / alternatives?" |
| [certd-store.md](certd-store.md) | The Postgres store's design + invariants | Working on persistence (roles, principals, KRL, active-cert guard) |
| [OPERATIONS.md](OPERATIONS.md) | Deploy topology + runbooks + scenarios | Deploying, rotating keys, or firefighting |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Per-surface threats + mitigations | Reviewing the attack surface |

## Canonical source of truth (one owner per fact-type)

Don't restate these — link to the owner. If a fact lives in two places it
will drift; keep it in one and point everything else there.

| Fact-type | Authoritative source |
|---|---|
| `certd` env vars | godoc atop [`../cmd/certd/main.go`](../cmd/certd/main.go) |
| `cert-agentd` env vars | godoc atop [`../cmd/cert-agentd/main.go`](../cmd/cert-agentd/main.go) |
| Key/cert hierarchy, trust topology, the gotchas | [architecture.md](architecture.md) |
| Two-tier design decisions | [two-tier-ca.md](two-tier-ca.md) |
| Store schema + data invariants | [certd-store.md](certd-store.md) |
| Threats + mitigations | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Deploy / rotation / recovery runbooks | [OPERATIONS.md](OPERATIONS.md) |
| Dev-rig cert material generation | [`../shared/certs/gen.sh`](../shared/certs/gen.sh) |
| Dev-rig service topology | [`../docker-compose.yml`](../docker-compose.yml) (header comment) |
