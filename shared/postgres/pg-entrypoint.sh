#!/bin/sh
# Postgres entrypoint for the ca dev rig — mTLS enabled by default.
#
# Runs as root (the default before docker-entrypoint.sh drops to the postgres
# user) so it can install the initdb script and stage the server key with the
# strict ownership + permissions postgres insists on before it will start.
#
# Env (set on the db container in docker-compose.yml):
#   PG_INIT_SCRIPT     initdb script to install (creates the app role)
#   POSTGRES_SSL_CERT  server certificate PEM (mkcert-signed; CN=postgres)
#   POSTGRES_SSL_KEY   server private key PEM
#   POSTGRES_SSL_CA    client-cert trust anchor — certd's X.509 issuer cert,
#                      so certd-issued authd-db-* leaves authenticate by CN
set -eu

if [ -n "${PG_INIT_SCRIPT:-}" ]; then
  cp "$PG_INIT_SCRIPT" /docker-entrypoint-initdb.d/init.sh
  chmod 755 /docker-entrypoint-initdb.d/init.sh
fi

# Postgres refuses to start if the private key is group/world-readable or not
# owned by the db user (uid 70 on alpine). The mounted copy lives on a
# read-only, root-owned volume, so stage a private copy under /tmp.
cp "$POSTGRES_SSL_KEY" /tmp/server.key
chown 70:70 /tmp/server.key
chmod 600 /tmp/server.key

# mTLS is the only way in: ssl=on, the cert/CA wired below, and the HBA file
# (pg_hba_cert.conf) rejects every non-TLS connection.
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c "ssl_cert_file=$POSTGRES_SSL_CERT" \
  -c ssl_key_file=/tmp/server.key \
  -c "ssl_ca_file=$POSTGRES_SSL_CA" \
  -c "hba_file=/shared/postgres/pg_hba_cert.conf"
