-- certd store (sqlite), migration 0005: reuse-detection lock escalation for
-- active_workload_cert — see the postgres 0005 migration for the rationale.
-- SQLite ALTER TABLE adds one column per statement.
ALTER TABLE active_workload_cert ADD COLUMN locked_at TEXT;
ALTER TABLE active_workload_cert ADD COLUMN locked_serial TEXT;
