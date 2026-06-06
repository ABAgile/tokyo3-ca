#!/usr/bin/env bash
# First-boot role setup for certd's Postgres store. Runs once via
# docker-entrypoint-initdb.d/. certd itself is POSTGRES_USER (the superuser
# that owns the "certd" database and runs its own migrations) — created by the
# image, not here.
#
# This script adds the extra login roles whose names MUST equal the CN of the
# client cert that authenticates them (Postgres `cert` auth maps CN → role):
#   auth_app   ← authd-db-app.crt   (CN auth_app)
#   auth_admin ← authd-db-admin.crt (CN auth_admin)
# Both are certd-issued certs cert-agentd provisions from
# shared/agent/workloads.json — here so those provisioned certs have a role to
# log in as and demonstrate end-to-end certd-issued mTLS to Postgres.
#
# All roles are PASSWORDLESS: authentication is by client-cert CN over TLS
# (pg_hba_cert.conf: `hostssl ... cert`) and by the trusted local socket for
# this bootstrap script. CREATE USER without a password is intentional.
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB" \
     -v db_name="$POSTGRES_DB" \
     --no-psqlrc <<'SQL'

-- App role: DML-only on objects the owner (certd) creates.
CREATE USER auth_app;
GRANT CONNECT ON DATABASE :"db_name" TO auth_app;
GRANT USAGE   ON SCHEMA  public      TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO auth_app;

-- Admin role: broader DDL rights for the provisioned admin cert.
CREATE USER auth_admin CREATEDB;
GRANT CONNECT ON DATABASE :"db_name" TO auth_admin;
GRANT ALL     ON SCHEMA  public      TO auth_admin;

SQL
