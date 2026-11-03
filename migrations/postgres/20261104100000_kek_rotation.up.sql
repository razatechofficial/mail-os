-- Key-encryption keys (KEKs) of the key manager (docs/key-manager-providers.md).
--
-- encryption_keys.kek_id names the KEK that wraps each data key:
-- software:<master key fingerprint>, pkcs11:<HSM key label> or
-- kms:<KMS key ARN>. Keys wrapped before this column existed have none; the
-- key manager's schedule re-wraps them under the current KEK and records it.
ALTER TABLE encryption_keys ADD COLUMN IF NOT EXISTS kek_id TEXT;

-- A KEK rotation re-wraps every data key under a new KEK. Data keys keep
-- their kid and material, so every sealed value keeps opening. One rotation
-- runs at a time; finished ones stay for the audit trail.
CREATE TABLE IF NOT EXISTS kek_rotations (
    id           UUID PRIMARY KEY,
    from_kek_id  TEXT        NOT NULL,
    to_kek_id    TEXT        NOT NULL,
    state        TEXT        NOT NULL,
    reason       TEXT        NOT NULL DEFAULT '',
    requested_by TEXT        NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    total        INTEGER     NOT NULL DEFAULT 0,
    rewrapped    INTEGER     NOT NULL DEFAULT 0,
    remaining    INTEGER     NOT NULL DEFAULT 0,
    failed       INTEGER     NOT NULL DEFAULT 0,
    last_error   TEXT        NOT NULL DEFAULT '',
    CONSTRAINT kek_rotations_state_chk CHECK (state IN ('rewrapping', 'completed')),
    CONSTRAINT kek_rotations_completed_chk CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
    CONSTRAINT kek_rotations_distinct_chk CHECK (from_kek_id <> to_kek_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS kek_rotations_one_running_idx ON kek_rotations ((true)) WHERE state = 'rewrapping';
CREATE INDEX IF NOT EXISTS kek_rotations_started_idx ON kek_rotations (started_at DESC);
