-- certd store (sqlite), migration 0006: owner-marker column for the
-- config-reconcile feature. A row's source records who manages it:
--   'config' — seeded/reconciled from CERTD_ROLES_FILE /
--              CERTD_MTLS_PRINCIPALS_FILE; `certd reconcile` adds, updates,
--              and PRUNES these to match the files (config is authoritative).
--   'portal' — created via the admin portal; `certd reconcile` never prunes
--              these and reports a name collision as a conflict.
-- Existing rows default to 'config': they were seeded from the JSON files on
-- first boot, which is exactly what reconcile then owns.
ALTER TABLE roles      ADD COLUMN source TEXT NOT NULL DEFAULT 'config';
ALTER TABLE principals ADD COLUMN source TEXT NOT NULL DEFAULT 'config';
