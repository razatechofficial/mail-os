DROP TABLE IF EXISTS audit_digests;
DROP INDEX IF EXISTS audit_events_seq_idx;
ALTER TABLE audit_events DROP COLUMN IF EXISTS seq;
