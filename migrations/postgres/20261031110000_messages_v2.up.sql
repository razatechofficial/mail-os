-- Messages v2: what an event asked for (topic, pinned template version,
-- data, the variables masked in views), who asked, and the retention
-- marker. Additive only: provider_msg_id keeps the provider's id.
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS reply_to            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS topic               VARCHAR(255),
    ADD COLUMN IF NOT EXISTS source              VARCHAR(64),
    ADD COLUMN IF NOT EXISTS template_id         VARCHAR(36),
    ADD COLUMN IF NOT EXISTS template_version_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS locale              VARCHAR(35),
    ADD COLUMN IF NOT EXISTS template_data       JSONB,
    ADD COLUMN IF NOT EXISTS secret_keys         TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS event_id            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS actor_type          VARCHAR(16),
    ADD COLUMN IF NOT EXISTS actor_id            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS last_error          TEXT,
    ADD COLUMN IF NOT EXISTS failed_at           TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancelled_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS body_purged_at      TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_messages_org_created ON messages (org_id, created_at DESC);
-- The retention purge scans messages whose body is still held.
CREATE INDEX IF NOT EXISTS idx_messages_purge ON messages (org_id, created_at) WHERE body_purged_at IS NULL;
-- The sweep re-enqueues queued messages and recovers stuck sends.
CREATE INDEX IF NOT EXISTS idx_messages_pending ON messages (status, updated_at) WHERE status IN ('queued', 'sending');
-- Daily limits count a provider's sends today.
CREATE INDEX IF NOT EXISTS idx_messages_provider_sent ON messages (provider_id, sent_at) WHERE provider_id IS NOT NULL;

-- Who added a manual suppression.
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);
