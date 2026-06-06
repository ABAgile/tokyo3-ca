-- certd store (postgres), migration 0005: reuse-detection lock escalation for
-- active_workload_cert. When a renewal presents a serial that is neither the
-- current nor the previous one while the recorded cert is still valid (a
-- possible clone), the identity is LOCKED: locked_at is stamped and every
-- later sign request for it is denied — past expiry too, so the auto-re-enroll
-- path does NOT fire — until an operator clears the row. locked_serial records
-- the offending serial for forensics. Both NULL means not locked.
ALTER TABLE active_workload_cert
    ADD COLUMN locked_at     TEXT,
    ADD COLUMN locked_serial TEXT;
