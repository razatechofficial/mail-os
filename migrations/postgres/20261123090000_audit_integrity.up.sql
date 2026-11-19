-- Tamper-evident audit log (PCI DSS 10.3.2-10.3.4), as IAM's: every audit
-- row gets a sequence number, and signed digests chain over runs of rows.
-- Existing rows are numbered in the order they were written.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS seq BIGINT;

WITH ordered AS (
    SELECT event_id, row_number() OVER (ORDER BY created_at, event_id) AS n FROM audit_events
)
UPDATE audit_events e SET seq = ordered.n FROM ordered WHERE ordered.event_id = e.event_id;

CREATE SEQUENCE IF NOT EXISTS audit_events_seq_seq OWNED BY audit_events.seq;
SELECT setval('audit_events_seq_seq', COALESCE((SELECT max(seq) FROM audit_events), 0) + 1, false);
ALTER TABLE audit_events
    ALTER COLUMN seq SET DEFAULT nextval('audit_events_seq_seq'),
    ALTER COLUMN seq SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_seq_idx ON audit_events (seq);

-- One digest per sealed run; from_seq is unique so two sealers racing
-- cannot both write the same run.
CREATE TABLE IF NOT EXISTS audit_digests (
    seq             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    from_seq        BIGINT NOT NULL UNIQUE,
    to_seq          BIGINT NOT NULL,
    record_count    INT NOT NULL,
    records_hash    CHAR(64) NOT NULL,
    previous_digest TEXT NOT NULL DEFAULT '',
    digest_hash     CHAR(64) NOT NULL UNIQUE,
    signature       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT audit_digests_range_chk CHECK (to_seq >= from_seq AND record_count > 0)
);
