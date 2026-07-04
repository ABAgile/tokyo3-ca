# Architecture — keys, certs, and trust topology

The cross-cutting map of tokyo3-ca's trust: the key/cert hierarchy, what
signs what, and which anchor each link pins. It exists because that picture
is otherwise spread across `cmd/certd/main.go` godoc, the README, OPERATIONS.md,
and `docker-compose.yml` comments — and those drift.

**Canonical sources (this doc links, does not duplicate):**
- Env-var reference → the godoc at the top of [`cmd/certd/main.go`](../cmd/certd/main.go).
- Two-tier rationale + ceremony/rotation runbooks → [two-tier-ca.md](two-tier-ca.md), [OPERATIONS.md](OPERATIONS.md) §3.
- Dev-rig material generation → [`shared/certs/gen.sh`](../shared/certs/gen.sh).

---

## 1. Three trust domains

certd issues into three independent trust domains. Conflating them is the
usual source of confusion:

| Domain | What it secures | Anchor consumers pin | Chained? |
|---|---|---|---|
| **Internal X.509 mesh** | certd ⇄ NATS / Postgres / cert-agentd, traefik→certd backend | the **root** (`certd-x509-ca.crt`) | yes (leaf → [intermediate →] root) |
| **HTTPS edge** | browser / host → traefik `:8443` | the **mkcert root** (`traefik-ca.crt`, in OS trust) | yes (mkcert) |
| **SSH** | SSH user/host certs | the **SSH CA pubkey** (`certd-signing.key.pub`) | no — SSH certs are chainless |

"One internal CA (the root), plus two edge anchors (mkcert HTTPS edge + SSH CA
pubkey)." mkcert touches **only** the traefik edge cert; the SSH CA key is its
own world and never goes in a TLS bundle.

---

## 2. X.509 key & cert hierarchy (two-tier — the rig default)

```
            OFFLINE — gen.sh / ceremony only; certd serve NEVER loads root.key
            ┌────────────────────────────────────────────────┐
            │ root.key  →  certd-x509-ca.crt                 │  Ed25519, self-signed
            │ self-signed ROOT, pathlen:1, CN=tokyo3-ca root │  the ONE mesh anchor
            └──────────────┬─────────────────────────────────┘
                           │ signs
        ┌──────────────────▼─────────┐
        │ certd-x509-int.crt         │
        │ INTERMEDIATE, CA:TRUE,     │
        │ pathlen:0                  │
        │ key → certd-x509-int.key.  │
        │ sealed (AES under seal.key)│
        └──────────┬─────────────────┘
                   │ signs bootstrap + runtime leaves
        ┌──────────▼───────────────────────────────────────────┐
        │ bootstrap leaves — nats, postgres, certd, certd-nats │
        │ certd-db, natsbox, cert-agentd                       │
        │ runtime leaves — cert-agentd renewals, authd         │
        │ workloads — all presented as leaf + intermediate     │
        └──────────────────────────────────────────────────────┘

  Everything chains to certd-x509-ca.crt (the ROOT). Consumers pin only the root;
  the intermediate travels inside each X.509 leaf's presented chain.

  SSH (parallel, chainless):
        certd-signing.key  ──signs──▶  SSH user/host certs
        certd-signing.key.pub  ◀──pinned by──  TrustedUserCAKeys / @cert-authority
```

### The files (under `shared/certs/`)

| File | Role | certd env |
|---|---|---|
| `root.key` | offline root signing key — signs the intermediate. **gen.sh/init-env artifact only; certd serve never loads it.** | — |
| `certd-x509-ca.crt` | self-signed **root** (pathlen:1) — the mesh anchor | `CERTD_CA_ROOT_CERT_FILE` (+ default `CERTD_CA_TRUST_BUNDLE`) |
| `seal.key` | 32-byte AES key sealing the intermediate (DEV ONLY) | `CERTD_CA_SEAL_KEY=file:…` |
| `certd-x509-int.crt` | **intermediate** issuer cert (root-signed) | `CERTD_CA_X509_CERT_FILE` |
| `certd-x509-int.key.sealed` | intermediate key, AES-256-GCM-sealed (base64); unsealed into memory at boot | `CERTD_CA_SEALED_KEY_FILE` |
| `certd-signing.key`(`.pub`) | **SSH** CA key (PKCS#8) + OpenSSH pubkey — SSH certs only | `CERTD_CA_KEY=file:…` |
| `traefik-ca.crt` / `traefik.{crt,key}` | mkcert root / traefik edge cert | — / traefik file provider |

---

## 3. What signs what

| Output | Signed by | Presented as |
|---|---|---|
| SSH user/host certs | `certd-signing.key` (`CERTD_CA_KEY`) | the cert (chainless; verifier pins the pubkey) |
| **Bootstrap** mesh leaves (`certd ca init-env`, offline) | the **intermediate** (generated then sealed during ceremony) | `leaf + intermediate` |
| **Runtime** X.509 leaves (sign API, renewals) | the **intermediate** (unsealed at boot) | `leaf + intermediate` |

Bootstrap leaves are issued by the same intermediate certd uses at runtime. The
init-env ceremony signs the intermediate with the root, uses the intermediate
key in-memory for initial server/workload leaves, then seals it for
`certd serve`.

---

## 4. Trust topology — who presents, who pins

Every internal mTLS channel pins the **one** root anchor (`certd-x509-ca.crt`),
in both directions:

| Channel | Server cert | Client cert(s) | Anchor (both ends) |
|---|---|---|---|
| certd API ⇄ cert-agentd | `certd.crt` (leaf+int) | agent `svid.pem` — bootstrap and renewed leaves carry intermediate | `certd-x509-ca.crt` |
| certd ⇄ NATS (+ natsbox, agent) | `nats.crt` (leaf+int) | `certd-nats`, `natsbox`, agent svid | `certd-x509-ca.crt` |
| certd ⇄ Postgres | `postgres.crt` (leaf+int) | `certd-db`, runtime `authd-db-*` (leaf+int) | `certd-x509-ca.crt` |
| traefik → certd (re-encrypt) | `certd.crt` (leaf+int) | — (traefik sends none) | `certd-x509-ca.crt` |
| browser/host → traefik (edge) | `traefik.crt` (mkcert) | — | mkcert root (`traefik-ca.crt`, OS trust) |
| SSH client → host | — | SSH cert (signed by `certd-signing.key`) | `certd-signing.key.pub` |

The agent reaches certd **directly** at `certd:8443` (never through traefik) so
its client cert isn't stripped — the sign API's SAN→principal auth depends on it.
The agent's anchor file (`svid_bundle.pem`, = the root) is seeded by
`cert-agentd-init` and kept fresh by polling `GET /api/v1/x509/trust-bundle`.

---

## 5. Two seams: signer vs sealer

Two distinct cryptographic jobs, two registries, both scheme-tagged on their
key reference (`file:<path>` vs everything-else):

| Seam | Resolver | Operation | `file:` binding | default binding |
|---|---|---|---|---|
| **Signer** (asymmetric) | `resolveCASigner` (`signer_source.go`) | Sign | PKCS#8 PEM load | AWS KMS (`aws_kms.go`) |
| **Sealer** (symmetric) | `resolveSealer` (`seal.go`) | Encrypt/Decrypt | AES-256-GCM, dev-only, loud warning (`seal_local.go`) | AWS KMS (`seal_aws_kms.go`) |

- Signer feeds `CERTD_CA_KEY` (SSH signer / single-tier CA) and the ceremony's
  `--root-key`. A bare ref (`arn:…`, alias) → KMS; `file:<path>` → PEM.
- Sealer feeds `CERTD_CA_SEAL_KEY`. Same scheme rule. The `file:` scheme is the
  dev opt-in (no build tag); it's compiled into every binary but logs a loud
  warning, because the AES key sits beside the ciphertext — not real protection.

---

## 6. Rotation cheatsheet

| Rotate | Cadence | Disruption | How |
|---|---|---|---|
| **Intermediate** | ~60% of its ~90d life | none (consumer-invisible) | re-run `issue-intermediate`, restart certd; old ≤24h leaves drain |
| **Root cert** (same key) | before expiry (~decade) | minimal | same-key re-mint; distribute via overlap trust bundle |
| **Root key** | rare (offline, off the hot path) | high (re-anchor everyone) | new key + overlap bundle (`certd ca rotate`) |
| **SSH CA key** | as needed | none (multi-key overlap) | `CERTD_SSH_CA_KEYS_FILE` old⊕new; verifiers poll `/api/v1/ssh/ca-keys` |

`CERTD_CA_TRUST_BUNDLE` (served at `/api/v1/x509/trust-bundle`) is the pull-based
propagation channel and can carry an overlap (old⊕new) bundle so a root-cert
refresh reaches every workload without manual re-anchoring. It defaults to the
**root** (`CERTD_CA_ROOT_CERT_FILE`) — see gotcha #4. Full runbooks: OPERATIONS.md §3.

---

## 7. Single-tier vs two-tier

Two-tier is the **rig** default, not certd's default. With `CERTD_CA_SEALED_KEY_FILE`
+ `CERTD_CA_SEAL_KEY` **unset**, certd is single-tier: one `CERTD_CA_KEY` signs
both SSH and X.509, and `CERTD_CA_X509_CERT_FILE` is *both* the issuer and the
anchor consumers pin (no root, no intermediate). The trust-bundle default falls
through to that issuer. Everything below the "what signs what" line collapses to
one key + one self-signed cert.

---

## 8. Non-obvious facts (the gotchas)

1. **`certd-x509-ca.crt` holds the ROOT, not the issuer.** The filename was kept
   from the single-tier issuer so every consumer reference is unchanged — but in
   two-tier it's the root anchor; the issuer is `certd-x509-int.crt`.
2. **Bootstrap and runtime leaves are intermediate-signed (`leaf+int`).** Both
   validate to the pinned root. `certd ca init-env` uses the intermediate key
   during the offline ceremony, then seals it for `certd serve`.
3. **The `file:` seal is dev-only.** Key beside ciphertext ⇒ no real at-rest
   protection; certd logs a loud warning. Production sets `CERTD_CA_SEAL_KEY` to a
   KMS ref.
4. **`CERTD_CA_TRUST_BUNDLE` must resolve to the root.** Its default is
   `CERTD_CA_ROOT_CERT_FILE` → `CERTD_CA_X509_CERT_FILE`; serving the *intermediate*
   would make pull-based consumers anchor it instead of the root.
5. **`root.key` is never loaded by `certd serve`.** It's a gen.sh / ceremony
   artifact. The key certd holds at runtime is the *SSH* key (`certd-signing.key`)
   plus the *unsealed intermediate* — never the root.
6. **mkcert is only at the traefik edge.** No internal link uses `traefik-ca.crt`; it
   anchors `traefik.crt` and nothing else.
