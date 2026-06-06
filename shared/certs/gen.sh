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

# certd_leaf NAME CN EKU SAN...
# Self-issues a leaf cert signed by the certd CA signing key, so it chains to
# certd-x509-ca.crt — the SINGLE CA for all internal mTLS (nats + postgres,
# both server and client certs, and every workload identity). Runs offline
# with no certd process — exactly the "self-issued bootstrap" path in
# OPERATIONS.md, which is what lets certd present a client cert to its own
# dependencies before any certd is up to issue one. NAME → $OUT/NAME.{crt,key}
# (Ed25519, matching the CA key); EKU is serverAuth or clientAuth; the SAN args
# are openssl SAN entries (DNS:…, IP:…, URI:spiffe://…). MUST be called AFTER
# the signing key + issuer cert exist.
certd_leaf() {
  local name=$1 cn=$2 eku=$3; shift 3
  step "$name (certd-issued, $eku)"
  local san="$1"; shift
  for s in "$@"; do san="$san,$s"; done
  openssl genpkey -algorithm ed25519 -out "$OUT/$name.key" >/dev/null 2>&1
  chmod 600 "$OUT/$name.key"
  openssl req -new -key "$OUT/$name.key" -subj "/CN=$cn" -out "$TMP/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$TMP/$name.csr" \
    -CA "$OUT/certd-x509-ca.crt" -CAkey "$OUT/certd-signing.key" -CAcreateserial \
    -days 3650 -out "$OUT/$name.crt" \
    -extfile <(printf 'basicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = %s\nsubjectAltName = %s\n' "$eku" "$san") \
    >/dev/null 2>&1
  chmod 644 "$OUT/$name.crt"
  ok
}

# ── certd HTTPS server cert (mkcert) ─────────────────────────────────────────
# certd's PUBLIC API cert is the ONE exception to the single-CA rule: it stays
# mkcert-signed so `curl https://localhost:8443/healthz` works from the host
# with no --cacert (mkcert's root is in the OS trust store), and cert-agentd
# verifies the API via ca.crt. Everything ELSE (the internal nats/postgres
# mesh) is certd-issued — see the certd_leaf block after the issuer cert below.
mkc_server "certd"        certd  localhost  127.0.0.1

# ── certd's CA signing key (X.509 + SSH) ─────────────────────────────────────
# One Ed25519 key signs everything certd issues: X.509/SPIFFE workload
# certs AND SSH user/host certs (certd loads it as a crypto.Signer, then
# wraps it for SSH). certd's CERTD_CA_KEY_FILE loader expects PKCS#8 PEM
# (-----BEGIN PRIVATE KEY-----), so mint it with openssl — NOT
# `ssh-keygen -t`, which emits the incompatible openssh-key-v1 envelope.
# certd-signing.key.pub is the OpenSSH-format CA public key SSH hosts pin
# via TrustedUserCAKeys; derive it from the private key with `ssh-keygen -y`.
#
# Generated once; rotation invalidates every cert it ever signed (rarely
# what you want for a dev rig). A pre-existing key in the wrong format
# (e.g. an old openssh-key-v1 file) is regenerated — certd can't load it.
if [[ -f "$OUT/certd-signing.key" ]] && grep -q "BEGIN PRIVATE KEY" "$OUT/certd-signing.key"; then
  step "certd-signing"
  skip "exists (PKCS#8) — delete certd-signing.key to rotate"
else
  step "certd-signing (CA key, PKCS#8)"
  # Rotating the key invalidates everything it ever signed, including the
  # X.509 issuer cert below — regenerate that too (rm forces it).
  rm -f "$OUT/certd-signing.key" "$OUT/certd-signing.key.pub" "$OUT/certd-x509-ca.crt"
  openssl genpkey -algorithm ed25519 -out "$OUT/certd-signing.key" >/dev/null 2>&1
  chmod 600 "$OUT/certd-signing.key"
  echo "$(ssh-keygen -y -f "$OUT/certd-signing.key") certd-user-ca" > "$OUT/certd-signing.key.pub"
  ok
fi

# ── certd's X.509 CA issuer cert (CERTD_CA_X509_CERT_FILE) ────────────────────
# The PUBLIC trust anchor for every X.509/SPIFFE leaf certd issues: a
# self-signed CA cert over the signing key above. Workloads doing mTLS put
# THIS cert in their trust bundle to verify a peer whose leaf was issued by
# certd — it is NOT ca.crt (that's mkcert's root, used only for certd's HTTPS
# server cert + the agent's bootstrap cert) and NOT certd-signing.key.pub
# (that's the OpenSSH-format SSH CA key). Same key, three public faces.
#
# certd, if started without CERTD_CA_X509_CERT_FILE, self-generates this at
# boot and never persists it — fine until two certd-issued workloads must
# verify each other across a certd restart. Persisting it here gives a stable
# anchor. Generated once; regenerated only when the signing key rotated (the
# rm above) — a fresh issuer cert over the SAME key still validates existing
# leaves (chains verify against the key, not the exact cert bytes).
if [[ -f "$OUT/certd-x509-ca.crt" ]]; then
  step "certd-x509-ca"
  skip "exists — delete certd-x509-ca.crt to regenerate"
else
  step "certd-x509-ca (issuer cert)"
  openssl req -x509 -new -key "$OUT/certd-signing.key" -out "$OUT/certd-x509-ca.crt" \
    -days 3650 -subj "/CN=tokyo3-ca" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" >/dev/null 2>&1
  ok
fi

# ── Internal mTLS mesh certs (certd-issued, chain to certd-x509-ca.crt) ───────
# Every cert below is signed by the CA key above, so the ONE anchor
# certd-x509-ca.crt verifies them all — no per-channel CA bundle. Servers
# (nats, postgres) and clients alike: NATS's --tlscacert, Postgres's
# ssl_ca_file, and each client's server-verify CA are all certd-x509-ca.crt.
# Self-issued here (offline) so the services that connect at boot — certd to
# NATS + Postgres, before any runtime issuance exists — already hold a cert
# the mesh trusts.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Server certs (serverAuth). SANs cover the compose hostname + loopback.
certd_leaf "nats"      nats      serverAuth  DNS:nats      DNS:localhost  IP:127.0.0.1
certd_leaf "postgres"  postgres  serverAuth  DNS:postgres  DNS:localhost  IP:127.0.0.1

# Client certs (clientAuth). For Postgres `cert` auth the CN MUST equal the
# connecting role; NATS has no per-subject auth, so its CNs are cosmetic.
certd_leaf "certd-nats"  certd  clientAuth  URI:spiffe://demo/workload/certd-nats
certd_leaf "natsbox"     natsbox  clientAuth  URI:spiffe://demo/workload/natsbox
# certd's Postgres client identity — CN=certd authenticates as the "certd"
# superuser role (POSTGRES_USER) that owns certd's own store.
certd_leaf "certd-db"    certd  clientAuth  URI:spiffe://demo/workload/certd-db
# cert-agentd's bootstrap client cert. certd-issued (not mkcert) so it
# authenticates to NATS from its very first connection; cert-agentd reuses the
# KEY as its workload key and renews the cert in place — runtime-renewed certs
# are signed by the same CA, so the anchor never changes. (Set the agent's
# CERT_AGENTD_ROTATE_KEY to mint a fresh key each renewal instead of reusing
# this one.)
#
# Its SAN is the agent's REAL workload identity (spiffe://tokyo3/authd/agent),
# NOT a demo/workload/* placeholder — that's the principal certd's inbound
# mTLS auth maps to groups (shared/policy/principals.json), and it's the same
# SAN the renewed cert carries (CERT_AGENTD_SPIFFE_URI), so the agent
# authenticates by the same principal on its first request and every renewal.
certd_leaf "cert-agentd"  cert-agentd  clientAuth  URI:spiffe://tokyo3/authd/agent

echo ""
echo "dev TLS material written to ./shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up    # _sync-shared tar-pipes ./shared/ + brings up the rig"
