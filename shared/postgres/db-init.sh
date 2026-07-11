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

CREATE ROLE certd_admin LOGIN;
CREATE ROLE certd_app LOGIN;
CREATE ROLE authd_admin LOGIN;
CREATE ROLE authd_app LOGIN;
CREATE ROLE vaultd_admin LOGIN;
CREATE ROLE vaultd_app LOGIN;

CREATE DATABASE certd OWNER certd_admin;
CREATE DATABASE authd OWNER authd_admin;
CREATE DATABASE vaultd OWNER vaultd_admin;

\connect certd

GRANT CONNECT ON DATABASE certd TO certd_app;
GRANT USAGE ON SCHEMA public TO certd_app;

ALTER DEFAULT PRIVILEGES FOR ROLE certd_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO certd_app;
ALTER DEFAULT PRIVILEGES FOR ROLE certd_admin IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO certd_app;

\connect authd

GRANT CONNECT ON DATABASE authd TO authd_app;
GRANT USAGE ON SCHEMA public TO authd_app;

ALTER DEFAULT PRIVILEGES FOR ROLE authd_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authd_app;
ALTER DEFAULT PRIVILEGES FOR ROLE authd_admin IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO authd_app;

\connect vaultd

GRANT CONNECT ON DATABASE vaultd TO vaultd_app;
GRANT USAGE ON SCHEMA public TO vaultd_app;

ALTER DEFAULT PRIVILEGES FOR ROLE vaultd_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vaultd_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vaultd_admin IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO vaultd_app;

SQL
