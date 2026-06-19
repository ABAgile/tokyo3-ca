# Design: two-tier X.509 CA (offline root + sealed intermediate) and SSH CA rotation

- **Status:** implemented — and the default in the docker rig (local `file:` seal; production uses a KMS seal key)
- **Date:** 2026-06-07
- **Scope:** `certd` X.509 issuance hierarchy + `cert-agentd` trust distribution; SSH CA key distribution.
- **See also:** [architecture.md](architecture.md) — the live key/cert hierarchy + trust-topology map (this doc is the *design rationale*; that one is the *as-built* picture).
- **Related:** [OPERATIONS.md](OPERATIONS.md) §2–4, [THREAT_MODEL.md](THREAT_MODEL.md),
  `internal/server/x509engine`, `cmd/certd/ca*.go`, `internal/agent/renew`.

---

## 1. Problem

Today `certd` is a **single-tier CA**. One signing key (`caSigner`, file or KMS) signs
*everything*: the self-signed root cert (`x509engine.NewSelfSignedCA`, `MaxPathLenZero:true`
— "no sub-CAs"), every X.509 leaf, and every SSH cert. `CERTD_CA_X509_CERT_FILE` is both the
cert certd signs under **and** the trust anchor every consumer pins.

Two consequences fall out of that:

1. **The root signing key is on the per-leaf hot path and can never be offline.** With ≤24 h
   leaves renewed at ~60 % TTL, the root key is invoked continuously. certd's runtime principal
   must hold `Sign` on the root at all times, so any compromise of the certd process / its IAM
   identity yields the root as a signing oracle — unbounded blast radius, recoverable only by a
   full root rotation + re-distribution of the anchor to every consumer. The architecture
   *structurally forbids* gating or air-gapping the root.

2. **There is no X.509 revocation.** No CRL is published, leaves carry no CDP/AIA, the revoke
   endpoint + store are SSH-only (`uint64` serial, KRL format), and no consumer
   revocation-checks (Go stdlib TLS ignores CRL/OCSP; the rig sets `POSTGRES_SSL_CA` but no
   `ssl_crl_file`; NATS `--tlsverify` is chain-only). So an issued cert is trusted until it
   expires.

Goal: **reduce the exposure and rotation cost of the root key**, while keeping the
expiry/rotation behaviour of leaves correct.

## 2. Decision

Adopt a **two-tier X.509 hierarchy**:

- **Root** — an asymmetric KMS key (or air-gapped file). Its `Sign` is **not wired into
  `certd serve`**. It is used only in a periodic **ceremony** to sign an intermediate.
- **Intermediate** — generated in the ceremony, **sealed** with a *separate symmetric* KMS key
  (`Encrypt`), shipped as ciphertext. At `serve` boot certd `Decrypt`s it into memory, builds an
  in-memory `signer.Signer`, and **signs X.509 leaves in-process** (no per-leaf KMS call, root
  never reachable online).
- **Chain** — leaves are served and presented as `leaf + intermediate`. **Consumers pin the
  root** and never change anchors across intermediate rotations.
- **SSH** — keeps its own signing key (different lifecycle from the X.509 intermediate), and
  gains a **published, pollable CA-key list** so SSH CA rotation is a cheap automated overlap
  (SSH has no cert chains, but `TrustedUserCAKeys` / `@cert-authority` accept multiple keys).

This is the SPIRE-shaped "KMS-backed upstream + in-memory server CA" pattern.

### What it buys

- Root `Sign` is **off the online attack surface**: a certd compromise yields at most a
  **bounded** intermediate oracle (≤ intermediate lifetime, cheap recovery, root anchor never
  moves), never the root.
- The root can finally be **offline / ceremony-only** (online minutes per quarter, not
  continuously).
- KMS comes **off the per-leaf hot path** (latency / cost / throttling), while the root key
  stays in KMS/HSM and the intermediate key never persists in plaintext.

### What it does *not* buy (kept explicit so the design rests on accurate ground)

- It does **not** add revocation. With no CRL, the intermediate's **lifetime is the
  compromise-containment window**; supersession does not revoke an old intermediate. See §5.
- For a **non-exportable KMS root**, call *volume* does not materially change key-material
  exfiltration odds — the win is capability-exposure + offline-ability, not "harder to steal the
  bytes".

## 3. Alternatives considered

| Option | Verdict |
|---|---|
| **Stay single-tier KMS** (root signs every leaf) | Simplest, no extra exposed key, and leaves already self-revoke in ≤24 h. **Correct choice if** root-key online-exposure is acceptable and KMS hot-path cost is not a problem. Rejected here because removing root `Sign` from the online surface is the stated goal. |
| **Ephemeral in-memory intermediate, regenerated every restart** | Rejected. Regenerating the key each boot forces the **root online to sign it on every restart** — the opposite of the goal (keeps root hot, lets a certd compromise mint rogue intermediates). With no CRL it also doesn't shorten the compromise window vs a persisted-key intermediate. |
| **Intermediate key in local hardware (TPM / PKCS#11 HSM / Nitro enclave)** | Strictly better at-rest than sealed-file (non-exportable *and* off the network-KMS hot path). Deferred: needs hardware/enclave availability + plumbing. The sealed-file design here is the pragmatic middle and can be swapped for this later behind the same signer seam. |
| **Build CRL / OCSP across the mesh** | Rejected as the primary lever. Postgres honours only a static `ssl_crl_file` (no OCSP); NATS (Go stdlib) honours neither — only its opt-in `ocsp_peer` (OCSP, needs a responder + AIA on every chain cert). Industry direction is *away* from real-time revocation toward short-lived certs (CA/B Forum lifetime cuts; SPIFFE uses ~1 h certs, no CRL/OCSP). A Postgres-only `ssl_crl_file` is the one cheap surgical add and is listed as future work (§9). |

## 4. Architecture

```
                 ┌───────────────────────────────┐
   OFFLINE  ───► │ Root CA  (KMS asym / air-gap)  │   IsCA, MaxPathLen=1
   (ceremony)    │  • signs intermediate only     │   10y, signs ~quarterly
                 └───────────────┬───────────────┘
                                 │ ceremony: SignIntermediateCA
                 ┌───────────────▼───────────────┐
   ONLINE  ────► │ Intermediate CA                │   IsCA, MaxPathLenZero
   (certd serve) │  • key sealed (KMS symmetric)  │   ~90d, signs every leaf
                 │  • decrypted to memory at boot │
                 └───────────────┬───────────────┘
                                 │ in-process SignWorkloadCert / SignServerCert
                 ┌───────────────▼───────────────┐
                 │ Leaf (workload SVID / server)  │   ≤24h, renewed at 60% TTL
                 │  presented as  leaf+intermediate│
                 └────────────────────────────────┘

  Consumers (NATS, Postgres, cert-agentd, certd inbound mTLS) pin the ROOT.
  Leaf carries its own intermediate in the chain → validates to the pinned root.
  Intermediate rotation = swap certd's issuer; consumers' anchor never moves.
```

SSH is a parallel, chainless hierarchy: certd holds an SSH CA key; verifiers trust the SSH CA
**public key(s)** directly via `TrustedUserCAKeys` / `@cert-authority`. Rotation is handled by
publishing a multi-key set and polling it (§7, Phase F).

## 5. Correctness invariants (carried-forward "double check")

1. `leaf.NotAfter ≤ intermediate.NotAfter` — **enforced by a clamp** (Phase A). Missing today;
   latent even in single-tier. Without it, in the final ≤24 h of any issuer's life certd would
   mint leaves that outlive their issuer → silent chain death at issuer expiry.
2. `intermediate.NotAfter ≤ root.NotAfter` — enforced by `SignIntermediateCA` (Phase C).
3. `intermediate.pubkey == unsealed signing key` — existing `issuerLoader` guard, re-keyed onto
   the X.509 signer (Phase D).
4. **Intermediate chains to the root and both are in-validity** — verified at boot, fail-closed
   (Phase D).
5. Path length: root `MaxPathLen=1`, intermediate `MaxPathLenZero=true` (Phase C).
6. The SSH CA public key **never churns as a side effect** of X.509 intermediate rotation (the
   signers are split; Phase D). SSH rotates only on its own schedule (Phase F).

The **anti-theft / active-cert guard** is already chain-agnostic (keys on the SPIFFE URI row,
`sign_x509.go`), so intermediate rotation does not trip it — no change needed.

## 6. Configuration

| Env (certd) | Meaning |
|---|---|
| `CERTD_CA_SEALED_KEY_FILE` | Ciphertext of the intermediate's PKCS#8 key (KMS-`Encrypt`ed). |
| `CERTD_CA_SEAL_KEY` | Seal key used to `Decrypt` the sealed key at boot. A bare ref (alias / uuid / arn) ⇒ **symmetric KMS**; `file:<path>` ⇒ a local AES-256 key (**dev only** — logs a loud warning, key sits beside the ciphertext). |
| `CERTD_CA_X509_CERT_FILE` | (re-purposed) the **intermediate** cert — what certd signs leaves under. |
| `CERTD_CA_ROOT_CERT_FILE` | the **root** cert — the trust anchor; chain-verified against the intermediate at boot. |
| `CERTD_CA_TRUST_BUNDLE` | default → `CERTD_CA_ROOT_CERT_FILE` (served at `/api/v1/x509/trust-bundle`). |
| `CERTD_CA_KEY` | unchanged — the **stable SSH** signer (no longer the X.509 issuer). `file:<path>` or a KMS key ref. |
| `CERTD_SSH_CA_KEYS_FILE` | operator-maintained `TrustedUserCAKeys`-format set (multi-key during overlap); served at `/api/v1/ssh/ca-keys`. Falls back to the live SSH CA key when unset. |

| Env (cert-agentd) | Meaning |
|---|---|
| `CERT_AGENTD_SSH_CA_KEYS_PATH` | where to write the polled `TrustedUserCAKeys` set (off when unset). |
| `CERT_AGENTD_SSH_CA_KEYS_REFRESH_SECONDS` | poll cadence; default 3600. |
| `CERT_AGENTD_SSH_CA_KEYS_RELOAD_CMD` | optional post-write hook (e.g. SIGHUP) for servers that cache the set. |

Single-tier remains the default: with `CERTD_CA_SEALED_KEY_FILE` unset, the X.509 signer falls
back to `caSigner` and behaviour is byte-identical to today.

## 7. Implementation phases

Phases **A** and **F** are independently valuable and have no two-tier dependency — ship either
first. **B** is the backbone; **C+D** deliver two-tier; **E** ships it.

### Phase A — leaf-`NotAfter` clamp *(standalone correctness fix)*
- `internal/server/x509engine/x509engine.go`: in `SignWorkloadCert` + `SignServerCert`, after
  building `tmpl`, clamp `tmpl.NotAfter = min(p.ValidBefore, caCert.NotAfter)`; in
  `validate`/`validateServer` reject `ValidAfter >= caCert.NotAfter`.
- `internal/server/api/sign_x509.go`: refuse + alert (`503` + audit) when
  `issuerCert.NotAfter.Sub(now) < maxX509CertTTL`; audit the clamped `valid_before`.
- Tests: clamp case + near-expiry rejection in `x509engine_test.go`.

### Phase B — chain plumbing *(required for any intermediate)*
- `internal/server/api/sign_x509.go`: add `Chain string` to `signX509Response`, built from
  `issuerCert.Raw` PEM. Precompute `s.issuerChainPEM` at `api.New` (empty when the issuer is
  self-signed → single-tier output unchanged).
- `internal/client/client.go`: add `Chain string` to `SignWorkloadResponse`.
- `internal/agent/renew/renewer.go`: `SignOnce` writes `resp.Certificate + resp.Chain`
  (leaf-first) to `CertOutputPath`, including the bundle-write path. `readCurrentSerial` reads
  only the first block (leaf) — unaffected.
- `cmd/certd/ca_issue.go`: `--ca-cert` is now the **intermediate**; `writeLeafOutputs` writes
  `leaf + intermediate`; add `--root-cert` and point `--bundle-out` at the **root**.
- Tests: chain assertions in client / renewer / `ca_issue` (`assertChainsTo` →
  leaf→intermediate→root).

### Phase C — intermediate builder + ceremony command
- `internal/server/x509engine/x509engine.go`:
  - `NewSelfSignedRootCA(...)` with `MaxPathLen=1` (keep `NewSelfSignedCA` for the dev
    single-tier path).
  - `SignIntermediateCA(rnd, rootSigner, rootCert, params)` → `IsCA:true`,
    `MaxPathLenZero:true`, `KeyUsage:CertSign|CRLSign|DigitalSignature`,
    `NotAfter ≤ rootCert.NotAfter` (enforced).
  - Update `x509engine_test.go:226` pathlen assertions (root vs intermediate now differ).
- `cmd/certd/ca_intermediate.go` (new) — `certd ca issue-intermediate`: resolve the **root**
  signer (`--root-key`), generate the intermediate keypair,
  `SignIntermediateCA`, then **seal** the key (`Encrypt` via `--seal-key`). Outputs:
  `--out-cert` (intermediate) + `--out-sealed-key` (ciphertext). Run on a restricted/air-gapped
  host where root `Sign` is enabled.

### Phase D — unseal at boot + split SSH / X.509 signers
- **Unseal seam:** new `Unsealer` interface `Decrypt(ctx, ciphertext) ([]byte, error)` + AWS impl
  in `cmd/certd/kms_seal.go` (uses `awskms.Decrypt`), registered like
  `RegisterKMSClientFactory`. The key is tiny → direct KMS `Encrypt`/`Decrypt`, no envelope
  (Decision 2).
- `cmd/certd/signer_source.go`: sealed-intermediate mode — when `CERTD_CA_SEALED_KEY_FILE` set,
  read ciphertext → `Decrypt` via `CERTD_CA_SEAL_KEY` → load PKCS#8 → in-memory
  `signer.Signer` (the **X.509 signer**).
- **Split the signer:** `api.Config` gains `X509Signer signer.Signer`; `sign_x509.go` uses
  `s.x509Signer`; SSH paths keep `CASigner`. `main.go`: `X509Signer` = sealed signer, falling
  back to `caSigner` when unconfigured.
- `cmd/certd/main.go` `loadX509Issuer`: guard `issuerLoader(x509Signer.Public())`; load
  `CERTD_CA_ROOT_CERT_FILE`; **verify intermediate chains to root + both in-validity at boot,
  fail-closed**; warn when the intermediate is within ~14 d of `NotAfter`.
- `healthz` (`server.go:195`): surface intermediate `NotAfter` + chains-to-root bool.

### Phase E — docs, rig, threat model
- `OPERATIONS.md`: new section (ceremony, boot env, quarterly rotation runbook, compromise
  recovery); update §2–3 to three artifacts (root cert = anchor, intermediate cert = issuer,
  sealed intermediate key = secret).
- `README.md`: replace the "ONE CA" framing with root-anchor + intermediate-issuer;
  `shared/certs/gen.sh` mints root + intermediate + sealed key; the mesh anchors
  (`CERTD_API_CLIENT_CA`, `POSTGRES_SSL_CA`, NATS `--tlscacert`, `CERT_AGENTD_CA`) → **root**.
- `THREAT_MODEL.md`: CA-key rows — root offline (online only at ceremony), intermediate
  sealed-at-rest + in-memory at runtime, blast radius bounded by intermediate lifetime.

### Phase F — SSH CA-key-list publish + poll *(independent of A–E)*
Near-verbatim clone of the X.509 trust-bundle endpoint + agent puller.
- **F1 — certd publish:** `internal/server/api/server.go` add `sshCAKeysPath` +
  `Config.SSHCAKeysPath`; route `GET /api/v1/ssh/ca-keys` → `handleSSHCAKeys`
  (`internal/server/api/ssh_ca_keys.go`, new). Serve `CERTD_SSH_CA_KEYS_FILE` verbatim
  (operator-maintained multi-key set for old⊕new overlap); else derive the live key via
  `ssh.MarshalAuthorizedKey(ssh.NewPublicKey(s.caSigner.Public()))`. **Never serve empty**
  (would empty verifiers' `TrustedUserCAKeys` → lockout). Unauthenticated, like the trust bundle.
  Wire `SSHCAKeysPath: os.Getenv("CERTD_SSH_CA_KEYS_FILE")` in `main.go`.
- **F2 — client:** `FetchSSHCAKeys(ctx) (string, error)` + `SSHCAKeysResponse` in
  `internal/client/client.go` (clone of `FetchTrustBundle`).
- **F3 — agent poller:** `cmd/cert-agentd/sshcakeys.go` (new) — clone of
  `buildTrustBundleRefresher` (atomic write, skip-if-unchanged, keep-current-on-error,
  run-once-up-front). Env per §6. Optional reload hook. Also write the host-cert
  `@cert-authority * <key>` known_hosts form for host-cert verification. Register in the runner
  group beside `trustBundleRefresher` (`cmd/cert-agentd/main.go:281`).

## 8. Operational runbooks

### Intermediate ceremony (≈ quarterly)
1. On a restricted/air-gapped host where root `Sign` is enabled:
   `certd ca issue-intermediate --root-key … --root-cert root.crt --seal-key … --cn "tokyo3-ca intermediate" --ttl 2160h --out-cert int.crt --out-sealed-key int.key.sealed`.
2. Distribute `int.crt` → `CERTD_CA_X509_CERT_FILE`, `int.key.sealed` →
   `CERTD_CA_SEALED_KEY_FILE`. **Restart certd** (signing key fixed at boot).
3. Old leaves (≤24 h) drain — they carry the *old* intermediate (still root-signed, in-validity),
   so they keep validating. **No consumer touches its anchor.**

Rotate at ~60 % of the intermediate's life (≈ every 54 d for a 90 d cert) so you never reach the
near-expiry clamp zone. Same-key extension (re-mint the intermediate cert over the same sealed
key to push `NotAfter`) hot-reloads without a restart (`issuerLoader` accepts a same-key issuer).

### Intermediate-key compromise recovery
Run the ceremony immediately. The old intermediate self-expires (no CRL); the root + every
consumer anchor are untouched; the window is bounded by the intermediate lifetime. This is the
whole point of the sacrificial-intermediate design.

### SSH CA rotation (automated overlap)
1. Generate the new SSH CA key. Edit `CERTD_SSH_CA_KEYS_FILE` to **old ⊕ new**. Verifiers poll →
   trust both. Wait ≥ refresh interval + margin.
2. Switch certd's SSH signer to the new key (**restart**).
3. New SSH certs sign under the new key; short-lived existing certs drain.
4. Edit the file to **new only**. Verifiers narrow on the next poll.

## 9. Out of scope / future work

- **Local-hardware intermediate** (TPM / PKCS#11 / Nitro enclave) behind the same signer seam —
  strictly better at-rest than sealed-file.
- **Postgres `ssl_crl_file`** — the one cheap surgical revocation add for the DB edge (root
  publishes a CRL; Postgres rejects a revoked intermediate). Useful but optional given ≤24 h
  leaves.
- **Full mesh revocation (CRL + OCSP responder + `ocsp_peer`)** — high standing-infra cost;
  deliberately not pursued. Expiry + bounded intermediate lifetime is the revocation story.
- **SSH still cannot match X.509's "anchor never moves"** — it has no chains, so a new SSH CA
  pubkey must reach every verifier's list. Phase F makes that automatic and non-breaking, but it
  is distribution-to-all-verifiers, a notch costlier than the X.509 path.

## 10. Open decisions

1. **SSH on a separate signer that rotates via overlap** (recommended; this design) vs pinning
   SSH to a permanently-stable key. Phase F makes overlap rotation cheap, so SSH is split from
   the X.509 intermediate but no longer forced immutable.
2. **Direct KMS `Encrypt`/`Decrypt`** for the sealed key (tiny key, simplest) vs envelope /
   data-key. Recommend direct.
3. **Root custody at ceremony:** KMS asymmetric key with `Sign` granted only to a ceremony
   principal, vs a truly air-gapped file key. Affects only the ceremony host, not certd.
4. **External `ssh-proxyd`** (separate repo) must re-read its trusted-CA set per connection or
   honour the reload hook — confirm/fix there; stock `sshd` re-reads `TrustedUserCAKeys` per
   authentication and needs no reload.
