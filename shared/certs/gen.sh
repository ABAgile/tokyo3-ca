#!/usr/bin/env bash
# Generate dev TLS material for the docker-compose rig, signed by
# mkcert's local root CA. Run on the HOST from the repo root:
#
#     make gen-certs
#     # or: bash shared/certs/gen.sh
#
# Material lands next to this script under shared/certs/. `make
# _sync-shared` tar-pipes the directory into the shared_data named
# volume, so containers see it at /shared/certs/.
#
# Requires:
#   - mkcert (auto-installed via `go install` if missing — Go env must
#     already be set up so the mkcert binary lands on PATH)
#   - openssl (mints the PKCS#8 Ed25519 CA signing key certd loads)
#   - ssh-keygen (any OpenSSH install) to derive the SSH CA public key
#   - go (builds certd once for the `certd ca issue-server` / `issue-workload`
#     cert steps — the same path production uses to seed infra/workloads)
#
# Uses the abagile/mkcert fork (https://github.com/abagile/mkcert@add-cn)
# so the first hostname argument becomes Subject CN.
#
# `mkcert -install` adds the local root CA to the OS + browser trust
# stores on first run, so:
#
#   - `curl https://localhost:8443/healthz` succeeds without --cacert
#   - Containers that mount ./certs/ca.crt as their trust bundle still
#     work too (we copy mkcert's rootCA.pem into ./certs/ca.crt).
#
# Idempotent: re-runs regenerate the leaf certs in place. The CA signing
# key (certd-signing.key + .pub) is only (re)generated when missing or in
# the wrong format — rotating it invalidates every cert it ever signed,
# which is rarely what you want for a dev rig.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR"
mkdir -p "$OUT"

step() { printf '  %-34s' "$1..."; }
ok()   { echo "ok"; }
skip() { echo "skip ($1)"; }

# ── Ensure mkcert (abagile fork) is available ────────────────────────────────
if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

# ── Root CA bundle (stable filename for containers) ──────────────────────────
step "ca.crt (mkcert root)"
cp "$CAROOT/rootCA.pem" "$OUT/ca.crt"
ok

# ── Helpers ──────────────────────────────────────────────────────────────────
mkc_server() {
  local name=$1; shift
  step "$name (server cert)"
  mkcert -cert-file "$OUT/$name.crt" -key-file "$OUT/$name.key" "$@" >/dev/null 2>&1
  ok
}

# ── traefik edge HTTPS cert (mkcert) ─────────────────────────────────────────
# The ONE mkcert-signed cert left. traefik terminates the host-facing HTTPS
# edge with it, so `curl https://localhost:8443/healthz` works from the host
# with no --cacert (mkcert's root is in the OS trust store). traefik then
# re-encrypts to certd over the internal mesh CA (see the serversTransport in
# shared/traefik/dynamic.yml). Everything BEHIND the edge — including certd's
# OWN listener cert (issue-server'd below) — is certd-issued and chains to
# certd-x509-ca.crt. SANs cover the host names the browser/curl hit the edge by:
# certd.localhost is the portal vhost (the traefik router Host-matches it),
# localhost + 127.0.0.1 keep the bare `curl https://localhost:8443/healthz` UX.
mkc_server "traefik"      certd.localhost  localhost  127.0.0.1

# ── certd's SSH CA signing key ───────────────────────────────────────────────
# In two-tier mode this Ed25519 key signs SSH user/host certs ONLY — X.509 is
# signed by the sealed intermediate (root.key / certd-x509-int.*, below), so
# certd serve loads this purely as its SSH signer (CERTD_CA_KEY_FILE) and never
# holds the root. certd's loader expects PKCS#8 PEM (-----BEGIN PRIVATE KEY-----),
# so mint it with openssl — NOT `ssh-keygen -t`, which emits the incompatible
# openssh-key-v1 envelope. certd-signing.key.pub is the OpenSSH-format CA public
# key SSH hosts pin via TrustedUserCAKeys; derive it with `ssh-keygen -y`.
#
# Generated once; rotation invalidates every cert it ever signed (rarely
# what you want for a dev rig). A pre-existing key in the wrong format
# (e.g. an old openssh-key-v1 file) is regenerated — certd can't load it.
if [[ -f "$OUT/certd-signing.key" ]] && grep -q "BEGIN PRIVATE KEY" "$OUT/certd-signing.key"; then
  step "certd-signing"
  skip "exists (PKCS#8) — delete certd-signing.key to rotate"
else
  step "certd-signing (SSH CA key, PKCS#8)"
  # SSH-only signer now (two-tier: X.509 is signed by the sealed intermediate,
  # not this key). Rotating it only affects SSH certs.
  rm -f "$OUT/certd-signing.key" "$OUT/certd-signing.key.pub"
  openssl genpkey -algorithm ed25519 -out "$OUT/certd-signing.key" >/dev/null 2>&1
  chmod 600 "$OUT/certd-signing.key"
  echo "$(ssh-keygen -y -f "$OUT/certd-signing.key") certd-user-ca" > "$OUT/certd-signing.key.pub"
  ok
fi

# ── Build certd (the intermediate ceremony + issue-{server,workload} below) ──
# Built once into a scratch dir and reused. issue-intermediate, issue-server and
# issue-workload all run through this binary — the same offline path production
# uses to seed the hierarchy + infra, built by the same x509engine the sign
# endpoint uses, so dev and prod bootstrap share one code path.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
CERTD_BIN="$TMP/certd"
step "build certd (ca subcommands)"
(cd "$REPO_ROOT" && go build -o "$CERTD_BIN" ./cmd/certd) >/dev/null 2>&1
ok

# ── Two-tier X.509 hierarchy: root + sealed intermediate (default) ───────────
# The rig runs certd's two-tier mode BY DEFAULT (docs/two-tier-ca.md):
#
#   root.key            offline root key — signs the intermediate (and, for the
#                       dev rig only, the static bootstrap leaves below). certd
#                       serve NEVER loads it.
#   certd-x509-ca.crt   self-signed ROOT (pathlen:1) — the ONE anchor every
#                       consumer pins (POSTGRES_SSL_CA, NATS --tlscacert,
#                       CERTD_API_CLIENT_CA, cert-agentd's bundle, traefik
#                       backend CA). Same filename as the old single-tier issuer
#                       so every consumer reference is unchanged — it just holds
#                       the root now, not the issuer.
#   seal.key            32-byte AES key sealing the intermediate private key.
#                       DEV ONLY — a local key beside the ciphertext is not real
#                       protection (certd logs a loud warning on use); production
#                       uses a KMS seal key. Consumed via CERTD_CA_SEAL_KEY=file:.
#   certd-x509-int.{crt,key.sealed}
#                       the intermediate — cert (certd's CERTD_CA_X509_CERT_FILE,
#                       what it signs leaves under) + AES-sealed key certd serve
#                       unseals into memory at boot.
#
# Generated once (like the SSH key — rotating the root invalidates everything);
# delete root.key to force a fresh hierarchy. certd-signing.key stays the
# separate SSH CA key, so certd serve never holds the root.
if [[ -f "$OUT/root.key" && -f "$OUT/certd-x509-ca.crt" && -f "$OUT/seal.key" && -f "$OUT/certd-x509-int.key.sealed" ]]; then
  step "two-tier root+intermediate"
  skip "exist — delete root.key to rotate"
else
  rm -f "$OUT/root.key" "$OUT/certd-x509-ca.crt" "$OUT/seal.key" \
        "$OUT/certd-x509-int.crt" "$OUT/certd-x509-int.key.sealed"
  step "root.key + certd-x509-ca.crt (self-signed root, pathlen:1)"
  openssl genpkey -algorithm ed25519 -out "$OUT/root.key" >/dev/null 2>&1
  chmod 600 "$OUT/root.key"
  openssl req -x509 -new -key "$OUT/root.key" -out "$OUT/certd-x509-ca.crt" \
    -days 3650 -subj "/CN=tokyo3-ca root" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  ok
  step "seal.key (local AES-256 seal — DEV ONLY)"
  openssl rand -out "$OUT/seal.key" 32 >/dev/null 2>&1
  chmod 600 "$OUT/seal.key"
  ok
  step "certd-x509-int (intermediate, root-signed + sealed)"
  "$CERTD_BIN" ca issue-intermediate \
    --root-key "file:$OUT/root.key" --root-cert "$OUT/certd-x509-ca.crt" \
    --seal-key "file:$OUT/seal.key" \
    --out-cert "$OUT/certd-x509-int.crt" \
    --out-sealed-key "$OUT/certd-x509-int.key.sealed" --force >/dev/null 2>&1
  ok
fi

# ── Internal mTLS mesh certs (bootstrap, root-signed) ────────────────────────
# Issued offline so the services that connect at boot (certd → NATS + Postgres)
# already hold a trusted cert. For the dev rig these STATIC bootstrap leaves are
# signed directly by the root (root.key) — it's a local file here, so this skips
# needing the sealed intermediate's plaintext key offline. They are leaf-only
# and chain straight to certd-x509-ca.crt (the root anchor). The certs certd
# issues at RUNTIME (cert-agentd renewals, authd workloads) are signed by the
# unsealed INTERMEDIATE and presented as leaf+intermediate — both validate
# against the same root anchor every consumer pins.

# issue_server NAME DNS... — TLS server cert (DNS SANs + loopback IP, serverAuth).
issue_server() {
  local name=$1; shift
  step "$name (issue-server)"
  local args=(ca issue-server --ca-cert "$OUT/certd-x509-ca.crt" --key "file:$OUT/root.key"
    --out-cert "$OUT/$name.crt" --out-key "$OUT/$name.key" --ip 127.0.0.1 --force)
  for d in "$@"; do args+=(--dns "$d"); done
  "$CERTD_BIN" "${args[@]}" >/dev/null 2>&1
  ok
}

# issue_workload NAME SPIFFE-URI [CN] — SPIFFE SVID (URI SAN, clientAuth+serverAuth).
issue_workload() {
  local name=$1 spiffe=$2 cn=${3:-}
  step "$name (issue-workload)"
  local args=(ca issue-workload --spiffe-uri "$spiffe" --key-type ed25519
    --ca-cert "$OUT/certd-x509-ca.crt" --key "file:$OUT/root.key"
    --out-cert "$OUT/$name.crt" --out-key "$OUT/$name.key" --force)
  [[ -n "$cn" ]] && args+=(--cn "$cn")
  "$CERTD_BIN" "${args[@]}" >/dev/null 2>&1
  ok
}

# Server certs — clients verify these by hostname, so they carry DNS SANs.
# certd's own listener cert is now in here too (no longer mkcert): cert-agentd
# reaches it DIRECTLY at https://certd:8443 and verifies it against the internal
# CA, and traefik re-encrypts to the same SAN. The mkcert hop lives only at the
# traefik edge above.
issue_server "certd"     certd     localhost
issue_server "nats"      nats      localhost
issue_server "postgres"  postgres  localhost

# Client/workload SVIDs — verified by chain (NATS) or CN (Postgres certd-db),
# so a URI SAN is enough. For Postgres `cert` auth the CN MUST equal the
# connecting role; NATS has no per-subject auth, so its CN is cosmetic.
issue_workload "certd-nats"  spiffe://demo/workload/certd-nats
issue_workload "natsbox"     spiffe://demo/workload/natsbox
# certd's Postgres client identity — CN=certd authenticates as the "certd"
# superuser role (POSTGRES_USER) that owns certd's own store.
issue_workload "certd-db"    spiffe://demo/workload/certd-db   certd
# cert-agentd's bootstrap identity. SAN = the agent's REAL workload identity
# (spiffe://tokyo3/authd/agent) — the principal certd's inbound mTLS maps to
# groups (shared/policy/principals.json) and the SAN the renewed cert carries
# (CERT_AGENTD_SPIFFE_URI) — so it authenticates the same on its first request
# and every renewal. The renewer reuses this Ed25519 key (set
# CERT_AGENTD_ROTATE_KEY to mint a fresh key each renewal instead).
issue_workload "cert-agentd"  spiffe://tokyo3/authd/agent

echo ""
echo "dev TLS material written to ./shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up    # _sync-shared tar-pipes ./shared/ + brings up the rig"
