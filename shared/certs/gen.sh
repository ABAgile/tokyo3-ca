#!/usr/bin/env bash
# Generate dev TLS material for docker-compose rig.
#
# CA-owned material is produced by `certd ca init-env` from bootstrap.yml:
# root + sealed intermediate, certd/NATS/Postgres server certs, certd client
# certs, cert-agentd bootstrap SVIDs, and SSH CA key. This script stays as local
# dev glue: install mkcert, mint the host-facing Traefik edge cert, build certd,
# and invoke the manifest-driven bootstrap wrapper.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
MANIFEST="$DIR/bootstrap.yml"

mkdir -p "$OUT"

step() { printf ' %-42s' "$1..."; }
ok() { echo "ok"; }

if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

step "traefik-ca.crt (mkcert root)"
rm -f "$OUT/ca.crt"
cp "$CAROOT/rootCA.pem" "$OUT/traefik-ca.crt"
ok

# ONE mkcert-signed cert remains: Traefik's host-facing edge cert. Traefik then
# re-encrypts to certd over the internal certd-issued mesh CA.
step "traefik (server cert)"
mkcert -cert-file "$OUT/traefik.crt" -key-file "$OUT/traefik.key" \
  certd.localhost traefik.localhost localhost 127.0.0.1 >/dev/null 2>&1
ok

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CERTD_BIN="$TMP/certd"

step "build certd (ca init-env)"
(cd "$REPO_ROOT" && go build -o "$CERTD_BIN" ./cmd/certd) >/dev/null 2>&1
ok

step "certd ca init-env"
"$CERTD_BIN" ca init-env "$MANIFEST" --out-dir "$OUT" --force >/dev/null
ok

echo ""
echo "dev TLS material written to ./shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up # syncs CA-local shared/ + downstream certs/ and brings up the mesh rig"
