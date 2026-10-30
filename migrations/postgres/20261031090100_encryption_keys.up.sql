-- Per-purpose AES-256 data keys of the key manager, each wrapped under
-- KEY_MANAGER_MASTER_KEY (contract §6; IAM's key-manager design). A sealed
-- value names its key: km1.<kid>.<data>.
CREATE TABLE IF NOT EXISTS encryption_keys (
    id         UUID PRIMARY KEY,
    kid        TEXT NOT NULL UNIQUE,
    purpose    TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'active',
    provider   TEXT NOT NULL DEFAULT 'software',
    key_ref    BYTEA NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    CONSTRAINT encryption_keys_purpose_chk CHECK (purpose IN ('provider', 'dkim', 'webhook')),
    CONSTRAINT encryption_keys_state_chk CHECK (state IN ('active', 'retired')),
    CONSTRAINT encryption_keys_kid_chk CHECK (kid ~ '^[A-Za-z0-9_-]{8,64}$'),
    CONSTRAINT encryption_keys_retired_chk CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS encryption_keys_one_active_idx ON encryption_keys (purpose) WHERE state = 'active';
