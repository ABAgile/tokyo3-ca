-- certd store (postgres), migration 0001: role table (policy.Store).
-- Multi-valued Role fields are JSON text (parity with the sqlite backend;
-- promote to JSONB later if the portal ever needs to query into them).
-- group_claim is indexed but NOT unique (RolesForGroups aggregates all
-- roles sharing a claim).
CREATE TABLE IF NOT EXISTS roles (
    name                      TEXT PRIMARY KEY,
    group_claim               TEXT   NOT NULL,
    allowed_principals        TEXT   NOT NULL DEFAULT '[]',
    host_patterns             TEXT   NOT NULL DEFAULT '[]',
    spiffe_patterns           TEXT   NOT NULL DEFAULT '[]',
    default_extensions        TEXT   NOT NULL DEFAULT '{}',
    max_user_cert_ttl_seconds BIGINT NOT NULL DEFAULT 0,
    max_host_cert_ttl_seconds BIGINT NOT NULL DEFAULT 0,
    max_x509_cert_ttl_seconds BIGINT NOT NULL DEFAULT 0,
    updated_at                TEXT   NOT NULL
);

CREATE INDEX IF NOT EXISTS roles_group_claim_idx ON roles (group_claim);
