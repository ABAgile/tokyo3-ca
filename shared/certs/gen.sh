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

mkc_client() {
  local name=$1; shift
  step "$name (client cert)"
  mkcert -client -cert-file "$OUT/$name.crt" -key-file "$OUT/$name.key" "$@" >/dev/null 2>&1
  ok
}

# ── X.509 leaf certs ─────────────────────────────────────────────────────────
# certd serves HTTPS on localhost:8443 (host) and certd:8443 (compose net).
mkc_server "certd"        certd  localhost  127.0.0.1

# cert-agentd's bootstrap client cert. Renewed in place by cert-agentd
# itself once it starts; the mkcert-signed copy here is only the
# bootstrap credential. The renewed cert is signed by certd's own
# signing key (not mkcert's root), which is why the rig leaves
# CERTD_API_CLIENT_CA unset in docker-compose.yml.
#
# -ecdsa is required: the agent's renewer is hardcoded to ECDSA P-256
# (renewer.go's parsePrivateKeyPEM loads the bootstrap key and rejects
# any non-ECDSA type), so the bootstrap key must be ECDSA — NOT mkcert's
# default RSA, which fails with "unsupported key type *rsa.PrivateKey".
mkc_client "cert-agentd"  -ecdsa  spiffe://demo/workload/cert-agentd  cert-agentd

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
  rm -f "$OUT/certd-signing.key" "$OUT/certd-signing.key.pub"
  openssl genpkey -algorithm ed25519 -out "$OUT/certd-signing.key" >/dev/null 2>&1
  chmod 600 "$OUT/certd-signing.key"
  echo "$(ssh-keygen -y -f "$OUT/certd-signing.key") certd-user-ca" > "$OUT/certd-signing.key.pub"
  ok
fi

echo ""
echo "dev TLS material written to ./shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up    # _sync-shared tar-pipes ./shared/ + brings up the rig"
