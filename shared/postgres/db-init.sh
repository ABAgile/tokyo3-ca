#!/usr/bin/env bash
# First-boot role/database setup for the shared tokyo3 mesh Postgres.
#
# The mesh stack hosts multiple service databases behind one mTLS-only
# Postgres listener. TCP authentication is still certificate-based:
# the client cert CN must match the login role (pg_hba_cert.conf).
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB" \
     --no-psqlrc <<'SQL'

CREATE ROLE certd LOGIN;
CREATE ROLE auth_admin LOGIN;
CREATE ROLE auth_app LOGIN;

CREATE DATABASE certd OWNER certd;
CREATE DATABASE authdb OWNER auth_admin;

\connect authdb

GRANT CONNECT ON DATABASE authdb TO auth_app;
GRANT USAGE ON SCHEMA public TO auth_app;

ALTER DEFAULT PRIVILEGES FOR ROLE auth_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_app;
ALTER DEFAULT PRIVILEGES FOR ROLE auth_admin IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO auth_app;

SQL
