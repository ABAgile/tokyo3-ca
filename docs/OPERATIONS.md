# tokyo3-ca operations runbook

Day-to-day operational guidance for running `certd` and
`cert-agentd` in production. Use alongside the per-binary godoc in
`cmd/*/main.go` (the authoritative env-var reference) and
[THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Deployment topology

```
                                         ┌─────────────────┐
            ┌───────────────────────────►│    OIDC IdP     │
            │     discovery + JWKS       └─────────────────┘
            │
┌───────────┴───────────┐                ┌─────────────────┐
│       certd (this)    │───────────────►│  NATS JetStream │
│  HTTPS  :8443         │  audit publish └─────────────────┘
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
   - Dev: `openssl genpkey -algorithm ed25519 -out ca.key`; `CERTD_CA_KEY=file:ca.key`.
   - Prod: provision an asymmetric SIGN_VERIFY key in your KMS (AWS KMS, GCP KMS, Vault Transit, or HSM); set `CERTD_CA_KEY` to its key ref (the AWS binding is compiled in by default). See **§3 Production CA bootstrap (KMS)** below.
2. **Pin a persistent X.509 issuer cert.** Set `CERTD_CA_X509_CERT_FILE` to a stable self-signed CA cert over the signing key. **Do not skip this in production:** when unset, certd self-signs a *fresh, ephemeral* issuer at every boot, so previously-issued leaf certs stop chain-validating after a restart. This cert (not the API server cert, not the SSH CA pubkey) is the trust anchor every workload pins to verify a certd-issued mTLS peer. See §3 for minting it with a KMS key.
3. **Configure mTLS for the API.**
   - `CERTD_API_CERT` + `CERTD_API_KEY` = the server certificate the workloads validate (a TLS *server* cert with a DNS SAN — typically from your platform CA / cert-manager, **not** from certd itself).
   - `CERTD_API_CLIENT_CA` = the CA bundle the *inbound* workload client certs are signed by (i.e. certd's own issuer cert from step 2, once agents present certd-issued mTLS identities).
4. **Provision OIDC verification** (humans-and-OIDC path) via `CERTD_OIDC_ISSUER` + matching JWKS reachability.
5. **Seed the role table.** Write `CERTD_ROLES_FILE` as a JSON array of `policy.Role` objects (see `internal/server/policy/policy.go` for the struct shape).
6. **Seed the workload registry.** Write `CERTD_MTLS_PRINCIPALS_FILE` as a JSON array of `mtls.Principal` (Name, SAN, Groups).
7. **Hook NATS** for audit publish: `CERTD_NATS_URL` + the per-stream TLS env vars. Without it the audit stream is a no-op (dev only).
8. **Set portal credentials.** `CERTD_PORTAL_USERNAME` + `CERTD_PORTAL_PASSWORD` if no upstream identity-aware proxy is in front; otherwise leave both empty and trust the edge. (The SSH session + access-audit views live in ssh-proxyd's own portal — certd's `/portal/audit` shows only certd's `ca_audit` events.)

Start the binary, hit `https://certd/healthz` to confirm it bound,
and follow with `/portal/` to confirm the auth gate behaves as
expected.

## 3. Production CA bootstrap (KMS)

The CA has **two** pieces of key material, and they are not the same
object:

| Artifact | What it is | Where it lives | Who sees it |
|---|---|---|---|
| **CA signing key** | the private key that signs every leaf | **KMS / HSM — never exported** | certd, via the signer abstraction |
| **X.509 issuer cert** | self-signed CA cert over that key's *public* half | a PEM file (`CERTD_CA_X509_CERT_FILE`) + every workload's trust bundle | everyone (it's public) |

The signing key is secret and stays in KMS; the issuer cert is public
and is the trust anchor you distribute. Bootstrapping production means:
provision the key, mint the issuer cert *using* that key (without ever
extracting it), run certd against both, and publish the issuer cert.

### Step 1 — provision the KMS key

Create an **asymmetric SIGN_VERIFY** key. Match the algorithm to what
certd's signer expects: Ed25519 is certd's default, and AWS KMS supports
it (`ECC_NIST_EDWARDS25519`, since 2025-11), so the key type carries
over unchanged. ECDSA P-256 is the portable fallback (GCP KMS has no
Ed25519); RSA works but is slower per-issuance.

```sh
# AWS — Ed25519 (matches certd's default CA key)
keyid=$(aws kms create-key --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description "tokyo3-ca signing key (prod, ed25519)" \
  --query KeyMetadata.KeyId --output text)
aws kms create-alias --alias-name alias/tokyo3-ca-signing \
  --target-key-id "$keyid"
# Use the alias ARN as CERTD_CA_KEY so key rotation doesn't churn config:
#   arn:aws:kms:<region>:<acct>:alias/tokyo3-ca-signing

# AWS — ECDSA P-256 (portable fallback; also set workload key_type=ecdsa-p256)
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "tokyo3-ca signing key (prod, ecdsa-p256)"

# GCP — no Ed25519; use ECDSA P-256
gcloud kms keys create tokyo3-ca-signing --location global \
  --keyring tokyo3-ca --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256
```

Lock the key policy down to certd's runtime principal (IAM role /
GCP service account / Vault policy): **`Sign` + `GetPublicKey` only** —
no `Decrypt`, no export, no scheduling-for-deletion from the app role.

### Step 2 — choose the runtime signing model

Both `certd serve` and `certd ca` resolve the CA key through one seam
(`resolveCASigner`) from a single scheme-tagged `CERTD_CA_KEY`:
`file:<path>` is a PKCS#8 file, anything else (a bare ARN / alias) is a
KMS key ref; unset ⇒ ephemeral (dev). Two options:

- **Model A — online KMS signing (recommended).** The key never leaves
  KMS; every issuance calls KMS `Sign`. The AWS KMS binding ships in-repo
  (`cmd/certd/aws_kms.go`) and is **compiled in by default** — no flag,
  no operator Go code:

  ```sh
  export CERTD_CA_KEY=arn:aws:kms:us-east-1:111:key/abc
  certd serve                              # serve + ca sign through KMS
  ```

  The adapter handles pubkey parse, algorithm/message-type selection, and
  ctx/timeout. Standard AWS credential resolution applies (IRSA / env /
  profile / IMDS). Cost: ~+4.4 MiB of binary for the SDK; a future
  `-tags` split can make it optional for non-KMS deployments.

  Key spec: AWS KMS supports **Ed25519** (`ECC_NIST_EDWARDS25519`, since
  2025-11 — certd's default, so the CA key type carries over unchanged),
  plus `ECC_NIST_P256` and RSA; GCP KMS lacks Ed25519, so use ECDSA P-256
  there. Budget for KMS latency + throttling on the issuance hot path —
  only the public key is cached, which the adapter does.

  Other backends (GCP KMS, Vault Transit, PKCS#11 HSM): implement the
  two-method `kms.Client` and register it the same way — see
  `internal/server/signer/kms/doc.go`.

- **Model B — KMS-wrapped key file (works with the default binary).**
  Generate the Ed25519 key, envelope-encrypt it with a KMS *symmetric*
  key, store the ciphertext in your secret store. At deploy, KMS
  `Decrypt` it into a tmpfs path and point `CERTD_CA_KEY=file:<path>` there.
  The key is protected at rest but is present in process memory / tmpfs
  at runtime — weaker than Model A. Acceptable when your KMS has no
  asymmetric signing or you can't run a custom build.

### Step 3 — mint the issuer cert (key stays in KMS)

The issuer cert is just a self-signature over the public key, so the
signing key performs exactly **one** `Sign` to create it. The
`certd ca bootstrap` subcommand does this, reusing the same signer seam
and `x509engine.NewSelfSignedCA` path `serve` uses:

```sh
# Model A (KMS): the key never leaves KMS; this is its one Sign.
certd ca bootstrap --key arn:aws:kms:us-east-1:111:key/abc \
  --cn "tokyo3-ca prod" --out /etc/tokyo3-ca/issuer.crt

# Model B (file key): the SAME command against the shipped binary,
# pointing at the decrypted key file instead.
certd ca bootstrap --key /run/tokyo3-ca/ca.key --cn "tokyo3-ca prod" \
  --out /etc/tokyo3-ca/issuer.crt
```

Run it once per CA generation and commit the resulting cert to config
management. It's a one-shot operator action, not a runtime path. (Under
Model B you can equivalently `openssl req -x509 -new -key <decrypted>.key
…` exactly as `shared/certs/gen.sh` does for dev — same cert.)

### Step 4 — wire and distribute

1. `CERTD_CA_KEY` — a KMS key ref on a KMS-bound build (Model A) **or** `file:<path>` (Model B).
2. `CERTD_CA_X509_CERT_FILE=/etc/tokyo3-ca/issuer.crt` — the cert from step 3.
3. Push `issuer.crt` to **every workload's trust bundle** (`CERT_AGENTD_WORKLOAD_CA` on agents; `AUTH_DB_CA` / `AUTH_NATS_CA` / `AUTH_WORKLOAD_CA` etc. on consumers) so they validate certd-issued peers. This is a *different* file from the bundle that verifies certd's HTTPS server cert.
4. Verify the chain before going live:
   ```sh
   # issue a throwaway workload cert, confirm it chains to the issuer
   openssl verify -CAfile issuer.crt sample-leaf.crt   # → sample-leaf.crt: OK
   ```

### Rotation note

Rotating the **issuer cert** over the **same** key is cheap: a new
self-signed cert with the same public key still validates every
existing leaf (chains verify against the key, not the cert bytes).
Re-mint with `certd ca bootstrap --force` and distribute — no bundle,
no reissuance. **No restart, either:** certd hot-reloads
`CERTD_CA_X509_CERT_FILE` (it refuses a cert whose key doesn't match
the live signing key, so only a same-key re-mint is accepted) and
`CERTD_API_CLIENT_CA`. Distribution is pull-based too — agents that set
`CERT_AGENTD_TRUST_BUNDLE_PATH` fetch the refreshed bundle from
`GET /api/v1/x509/trust-bundle` on their own cadence.

Rotating the **key** is the disruptive operation. `certd ca rotate`
mints the new issuer cert from the new key and emits an overlap trust
bundle (old ⊕ new) so consumers trust both while old-key leaves drain:

```sh
certd ca rotate --key new-ca.key --out issuer-new.crt \
  --old issuer.crt --bundle-out trust-bundle.crt
# distribute trust-bundle.crt everywhere BEFORE cutting issuance to new-ca.key;
# once all old-key leaves have expired, drop the old cert:
certd ca bundle --out trust-bundle.crt issuer-new.crt
```

The `CERTD_API_CLIENT_CA` widen→narrow and the served trust bundle both
hot-reload (and agents auto-pull), so the only restart a key rotation
still needs is the one that swaps certd onto the new **signing key**
(`CERTD_CA_KEY`) — the signing key is loaded
once at boot, and the issuer reloader deliberately refuses a new-key
issuer until that restart so chains never break mid-flight.

See *Rotate the CA key* below for the full cutover sequence.

### Two-tier: offline root + sealed intermediate (optional)

> Hierarchy + trust-topology map: [architecture.md](architecture.md).

By default certd is single-tier: one signing key signs every SSH and X.509
leaf, and `CERTD_CA_X509_CERT_FILE` is both the issuer and the anchor consumers
pin. The optional **two-tier** mode keeps the asymmetric **root** offline and
signs X.509 leaves with a short-lived **intermediate** whose key certd unseals
into memory at boot — so the root's `Sign` never sits on the online issuance
path, and a certd compromise yields only a bounded, cheaply-rotated
intermediate. SSH is unaffected (it keeps signing with
`CERTD_CA_KEY`). Full rationale + design:
[two-tier-ca.md](two-tier-ca.md).

**Artifacts** (two-tier splits single-tier's signing-key + issuer apart):

| Artifact | What | Where |
|---|---|---|
| Root key | asymmetric; signs only the intermediate | offline / ceremony-only (KMS or air-gapped file) |
| Root cert | the trust anchor consumers pin | `CERTD_CA_ROOT_CERT_FILE` + every consumer CA bundle |
| Seal key | symmetric; wraps the intermediate key | KMS (`CERTD_CA_SEAL_KEY`); `file:<path>` selects a local AES-256 key for dev rigs (logs a loud warning — not for production) |
| Intermediate cert | what certd signs leaves under | `CERTD_CA_X509_CERT_FILE` |
| Sealed intermediate key | base64 KMS-ciphertext, unsealed at boot | `CERTD_CA_SEALED_KEY_FILE` |

**Ceremony — mint + seal the intermediate** (on a restricted/air-gapped host
where the root's `Sign` is enabled):

```sh
certd ca issue-intermediate \
  --root-key arn:aws:kms:…:key/ROOT  --root-cert root.crt \
  --seal-key arn:aws:kms:…:key/SEAL \
  --cn "tokyo3-ca intermediate" --ttl 2160h \
  --out-cert intermediate.crt --out-sealed-key intermediate.key.sealed
```

Then set `CERTD_CA_X509_CERT_FILE=intermediate.crt`,
`CERTD_CA_SEALED_KEY_FILE=intermediate.key.sealed`, `CERTD_CA_SEAL_KEY`, and
`CERTD_CA_ROOT_CERT_FILE=root.crt`. The **root cert is the anchor** — push it to
`CERTD_API_CLIENT_CA`, `POSTGRES_SSL_CA`, NATS `--tlscacert`, and
`CERT_AGENTD_CA`. At boot certd unseals the key, verifies the intermediate
chains to the root (failing closed otherwise), and signs leaves with it; each
leaf is served as `leaf+intermediate`, so it chains to the pinned root.

**Rotate the intermediate (routine, consumer-invisible).** Re-run the ceremony
at ~60% of the intermediate's life, drop the new `intermediate.crt` +
`intermediate.key.sealed`, and **restart certd** (the signing key is fixed at
boot). Old ≤24h leaves drain — they carry the *old* intermediate, still
root-signed and in-validity — so nothing breaks and **no consumer changes its
anchor**. A same-key re-mint (push the intermediate cert's `NotAfter` out
without changing the key) hot-reloads with no restart.

**Intermediate-key compromise recovery.** Re-run the ceremony immediately. The
old intermediate self-expires — there is **no X.509 CRL**, so the
intermediate's lifetime *is* the containment window — while the root and every
consumer anchor stay untouched. Keep the intermediate short (≈90d file-sealed;
longer only with hardware key custody). The unsealed key lives in plaintext
process memory at runtime (no `mlock` — see [THREAT_MODEL.md](THREAT_MODEL.md)
§S2 #2/#5); local-hardware custody (TPM/enclave) is the stronger option.

**The dev rig runs two-tier by default.** `gen.sh` mints the root + sealed
intermediate and `docker-compose.yml` wires `CERTD_CA_SEAL_KEY=file:/shared/certs/seal.key`
— a local AES-256 seal (certd logs a loud warning), so the rig exercises two-tier
end to end without KMS. Production sets `CERTD_CA_SEAL_KEY` to a KMS key ref.

## 4. Common scenarios

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

### Rotate the SSH CA key

SSH certs have no chain — verifiers trust the SSH CA public key directly — but
`TrustedUserCAKeys` accepts multiple keys, so rotation is a non-breaking
**overlap**, and certd publishes the current set for verifiers to poll:

1. Generate the new SSH CA key. Point `CERTD_SSH_CA_KEYS_FILE` at a file listing
   **old ⊕ new** pubkeys (TrustedUserCAKeys format); it is served at
   `GET /api/v1/ssh/ca-keys`. Verifiers running `cert-agentd` with
   `CERT_AGENTD_SSH_CA_KEYS_PATH` set pull the set on their poll cadence
   (default 1h) and rewrite their `TrustedUserCAKeys` — now trusting both. Wait
   ≥ one poll interval + margin.
2. Switch certd's SSH signing key (`CERTD_CA_KEY`) to
   the new key and **restart** (the signing key is fixed at boot).
3. New SSH certs sign under the new key; short-lived existing certs drain.
4. Edit `CERTD_SSH_CA_KEYS_FILE` to **new only**; verifiers narrow on the next
   poll.

stock `sshd` re-reads the `TrustedUserCAKeys` *file* per authentication, so the
poller's rewrite is picked up without a reload. With `CERTD_SSH_CA_KEYS_FILE`
unset the endpoint serves the single live CA key, so the poll still works in
steady state (no overlap to publish).

### Add a new tunnel host

1. Issue the workload an mTLS cert with a SPIFFE URI of the form
   `spiffe://<trust-domain>/host/<fqdn>`. `cert-agentd` on that
   host can renew the cert thereafter, but the **initial** cert is
   operator-bootstrapped — mint it with `certd ca issue-workload`
   (see *Bootstrap a workload with a self-issued mTLS cert* below) and
   deliver it via a Kubernetes secret / baked image / config mgmt.
2. Register the workload identity in `CERTD_MTLS_PRINCIPALS_FILE`:
   `{"name":"db-1.prod","san":"spiffe://td/host/db-1.prod","groups":["ssh-tunnel-host"]}`.
   Apply it with `certd reconcile --apply` (DB-backed) — see *Reconcile
   config to the database* below. (Without a DB the file only seeds an
   empty in-memory store, so a restart is still needed.)
3. Add a role in `CERTD_ROLES_FILE` that grants the new group
   permission to sign host certs (or reuse an existing
   `ssh-tunnel-host` role), then `certd reconcile --apply`.
4. The workload's `ssh-tunneld` picks up the trust-bundle and
   starts renewing on the next cycle.

### Reconcile config to the database (GitOps)

With a DB backend (`CERTD_DATABASE_URL`), `CERTD_ROLES_FILE` /
`CERTD_MTLS_PRINCIPALS_FILE` only **seed** an empty database on first boot;
later file edits do nothing until reconciled. `certd reconcile` applies them:

```bash
# Dry-run (default): print the add/update/prune/conflict plan, change nothing.
certd reconcile

# Apply. Config is authoritative over rows it owns (source=config): it adds,
# updates, and PRUNES them to match the files. Portal-created rows
# (source=portal) are never pruned.
certd reconcile --apply

# Scope to one table, or keep config-orphans instead of pruning:
certd reconcile --apply --roles-only
certd reconcile --apply --prune=false

# A file entry colliding with a portal-created row is a conflict (skipped +
# warned). Take ownership of it (rewrite as source=config) with:
certd reconcile --apply --adopt
```

Run it out-of-band from CD against the same `CERTD_DATABASE_URL` certd serves
(it opens its own connection — no server endpoint, no extra auth surface). The
applied counts are written to the structured log (shipped to NATS via applog
when configured). Reconcile is idempotent — a second run with an unchanged
file is a no-op.

### Enable native OIDC login for the portal

Multi-user portal access (instead of single shared Basic-auth creds):

1. **Mint the admin group in the IdP.** In `tokyo3-auth`, create a SCIM group
   named `ca-portal-admin` (`/portal/admin/groups/new`) and assign the CA
   operators to it.
2. **Register the portal as an OIDC client** in the IdP with redirect URI
   `https://<certd-host>/portal/auth/callback` and scopes
   `openid email profile groups` (confidential client — it gets a secret).
3. **Configure certd** (alongside the existing portal serve env):
   ```bash
   export CERTD_PORTAL_OIDC_ISSUER=https://id.example.com
   export CERTD_PORTAL_OIDC_CLIENT_ID=<client_id>
   export CERTD_PORTAL_OIDC_CLIENT_SECRET=<client_secret>
   export CERTD_PORTAL_OIDC_REDIRECT_URL=https://<certd-host>/portal/auth/callback
   export CERTD_PORTAL_ADMIN_GROUP=ca-portal-admin          # default; "" ⇒ any authed user
   export CERTD_PORTAL_SESSION_KEY=$(openssl rand -hex 32)  # 32-byte cookie-sealing key
   ```
   When all are set, `/portal/*` requires OIDC login + `ca-portal-admin`
   membership; the Basic-auth vars are ignored. Portal role/principal edits are
   then audited as `oidc:<email>`. Rotating `CERTD_PORTAL_SESSION_KEY`
   invalidates all live sessions (forces re-login).

### Bootstrap a workload with a self-issued mTLS cert

When a workload's **first** mTLS cert is minted offline rather than
issued through certd's sign endpoint, the first certd renewal does
**not** trip the renewal/anti-theft guard. Mint it with:

```sh
certd ca issue-workload \
  --spiffe-uri spiffe://td/host/db-1 \   # the identity it will renew under
  --ca-cert issuer.crt --key arn:… \     # (or --key file:ca.key) — signs through KMS
  --out-cert svid.pem --out-key svid.key --bundle-out svid_bundle.pem
```

`certd ca issue-workload` (SPIFFE SVID; its sibling `certd ca issue-server`
mints DNS-SAN listener certs) is the offline twin of the sign endpoint: it
generates the keypair and signs the leaf through the same signer seam
(so it works with a KMS key, where `openssl` cannot) and the same
x509engine builder. A separate bootstrap PKI, or `openssl` signing
directly with a *file* CA key, works too. The common case: seeding
certd's own client identity so it can reach Postgres / NATS over mTLS
before any certd is running to issue that cert (the classic CA bootstrap
cycle).

Why it's safe: the guard keys on the per-identity row in
`active_workload_cert` (PRIMARY KEY = the SPIFFE URI), **not** on the
presented cert's chain or serial. A self-issued cert was never recorded
by the sign path, so the first renewal for that SPIFFE identity finds no
row and is processed as first enrollment — serial continuity begins at
certd's first mint, and the offline cert's serial is never compared.
This is chain-agnostic: it holds whether the bootstrap cert is signed by
the CA key or by a separate bootstrap CA. (The guard only exists when
`CERTD_DATABASE_URL` is set; with no persistent store it is inactive.)

The one failure mode is a **leftover row** for that identity — you are
re-bootstrapping over a retained database, rotated the CA but kept the
`active_workload_cert` rows, or certd previously minted a cert for this
identity. If that recorded cert is still inside its validity window, the
first renewal presenting the self-issued serial is treated as a possible
clone and **the identity is LOCKED**: it gets a `403` and an
`x509.workload_cert.locked` audit event, and — crucially — the lock does
**not** clear on expiry (no auto-re-enroll), so the only resolution is to
clear the row (see *Recover a locked workload identity* below). A
genuinely fresh bootstrap database has no rows, so the clean path needs
none of this.

### Recover a locked workload identity

When a renewal presents a serial that is neither the current nor the
one-step-previous one **while the recorded cert is still valid**, the
reuse-detection guard escalates: it stamps `locked_at` + `locked_serial`
on the `active_workload_cert` row and denies that identity on **every**
subsequent sign request — past expiry too — emitting
`x509.workload_cert.locked`. The lock is a deliberate **halt-and-
investigate** signal; it does not auto-heal, so "wait it out" is not a
recovery path. Triage → clear certd state → reset the agent only as far
as needed.

**0. Investigate (don't reflexively clear).** Pull the
`x509.workload_cert.locked` event(s) from the audit stream — they carry
`presented_serial`, `locked_serial`, `current_serial`, `previous_serial`,
`locked_at`, and the caller. Decide which case you're in:
- **Theft / clone** — the offending serial came from a host that
  shouldn't hold this identity (two live holders).
- **Benign** — the agent reverted to an old cert: VM snapshot/backup
  restore, deployment rollback, a baked-in stale `svid.pem`, clock skew,
  or re-bootstrapping over a *retained* database.

**1. Clear the certd-side state.** Deleting the row clears the lock
**and** the serial chain, so the next request is a clean first-enrollment
(there is no partial "unlock that keeps continuity"):

```sql
DELETE FROM active_workload_cert WHERE identity = 'spiffe://<trust-domain>/<path>';
```

Direct DB op (no API/portal control yet); same statement on the sqlite
dev backend. This also resets the leftover-state bootstrap case above.

**2. Reset the agent — only as much as needed.** While locked, the agent
keeps retrying (each 403 is a sign failure → retry on
`CERT_AGENTD`'s backoff), so recovery depends on its on-disk cert:
- **Benign + `svid.pem` still TLS-valid** → nothing on the agent. Its
  next retry hits the now-empty record, re-enrolls, and the renewer
  overwrites `svid.pem`. Bounce the agent only to skip the wait.
- **Lock outlived the cert TTL** (it couldn't renew while locked, so
  `svid.pem` expired and can no longer complete the mTLS handshake to
  reach the sign endpoint) → **re-bootstrap + restart**:
  ```sh
  certd ca issue-workload --spiffe-uri spiffe://<trust-domain>/<path> \
    --ca-cert issuer.crt --key …  \
    --out-cert svid.pem --out-key svid.key --bundle-out svid_bundle.pem
  ```
  drop `svid.{pem,key}` onto the host (the agent's writable `/certs` /
  `agent_state`) and restart cert-agentd.
- **Confirmed theft** → treat the key as compromised: re-bootstrap with a
  **fresh keypair** (the command above generates one — do *not* keep the
  old `svid.key`), restart, and remediate the source host. Keep workload
  TTLs short — the lock halts *new* issuance, but a stolen leaf stays
  usable until its own TTL lapses (there is no X.509 workload-revocation
  list in this repo; short TTL + the lock are the containment).

**3. Fix the root cause for benign re-locks.** If something keeps making
the agent present a stale serial — a snapshot-restore loop, a read-only
image with a baked old cert, clock skew — clearing the row only helps
until the next renewal re-locks it. Fix the source (give the agent a
writable `svid.pem`, stop restoring stale state).

**Ordering:** clear the row **before** re-bootstrapping — a locked row
denies the agent regardless of which cert it presents, so a fresh
bootstrap cert won't take until the lock is gone. **Verify:** a fresh
`x509.workload_cert.signed` for the identity, a clean renewal log, and a
new `current_serial` with no `locked_at`. **Dev rig:** `make clean-all`
(then `make gen-certs && make docker-up`) is the full from-scratch reset.

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

## 5. cert-agentd operational notes

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

### CA-bundle rotation (zero-restart)

`CERT_AGENTD_CA` is mtime-polled every 30s. Operators can drop in
a new bundle (typically `[OLD, NEW]` during a rotation overlap
window) and the agent picks it up on the next tick — no restart
required. Read failures keep the previous pool live and log at
warn (`CA bundle reload failed; keeping previous pool`) so a
corrupt drop-in never opens a trust window.

Rotation workflow:

1. Drop `[OLD, NEW]` bundle on every host. Wait ≥30s + safety
   margin for every agent's poll to fire.
2. Switch certd's signing key from OLD to NEW. This still
   requires a certd restart — the signing key isn't hot-reloaded.
3. Wait for cert-agentd's normal renewal cadence (~60% TTL) to
   roll every workload onto NEW-signed leafs. Monitor via certd's
   audit stream.
4. Drop `[NEW]` bundle on every host. Trust set narrows back to
   single-CA on the next mtime poll.

The TLS material the agent presents to certd uses
`InsecureSkipVerify + VerifyConnection` rather than the standard
verifier so each handshake reads the *current* pool snapshot
rather than the one captured at config-construction time;
hostname + chain verification still run inside the callback.

### When to restart cert-agentd

- Configuration changes (env vars) — restart.
- KMS / certd endpoint change — restart.
- Workload cert revoked: the existing cert keeps validating
  upstream until it expires OR the next renewal fails (revoked
  cert can't authenticate to certd to refresh). Restart isn't
  needed but won't hurt.

## 6. Monitoring hooks

| Probe                                  | What it confirms                                           |
|----------------------------------------|------------------------------------------------------------|
| `GET https://certd/healthz`            | certd HTTP server is up + reports CA pubkey hash           |
| `GET https://certd/portal/healthz`     | Portal mux is up (exempt from Basic auth)                  |
| NATS subject `ca.audit.events`         | Tail for every issued / denied / revoked cert              |
| NATS subject `ssh.audit.events`        | Tail for every SSH session lifecycle event                 |
| certd structured logs                  | INFO on every successful sign; WARN on audit failures      |
| cert-agentd structured logs            | INFO on each renewal; WARN on certd-unreachable bursts     |
| Portal `/audit` page                   | certd's own cert issuance / denial / revocation events     |

## 7. Known limitations

- **No bulk-import endpoint** for the revocation set. Use the
  `POST /api/v1/ssh/revoke` endpoint in a loop.
- **No live hot-reload** for `CERTD_ROLES_FILE` / `CERTD_MTLS_PRINCIPALS_FILE`.
  With a DB backend, apply file edits with `certd reconcile --apply` (see
  *Reconcile config to the database*) — no restart. Without a DB the files
  only seed the in-memory stores, so a restart is still needed there.
- **In-memory revocation store** — restart clears it; back via
  audit-log replay or a future persistent backend.
- **No per-org rate limiting** at the API. Front certd with a
  rate-limiting edge if needed.
- **No API/portal control to clear an active-cert record.** Resetting a
  workload's rotation state (e.g. to re-bootstrap with a self-issued
  cert) is a direct `DELETE FROM active_workload_cert` — see *Bootstrap a
  workload with a self-issued mTLS cert* above.
