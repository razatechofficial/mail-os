-- Provider delivery events (delivered, bounced, complained, deferred):
-- when the provider says it happened and the provider's event key, so a
-- redelivered webhook is recorded once.
ALTER TABLE message_events
    ADD COLUMN IF NOT EXISTS provider_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS event_key   VARCHAR(160),
    ADD COLUMN IF NOT EXISTS reason      TEXT,
    ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS uq_message_events_key ON message_events (message_id, type, event_key)
    WHERE event_key IS NOT NULL;

-- A webhook names the message by the provider's id when it does not echo
-- MailOS's own.
CREATE INDEX IF NOT EXISTS idx_messages_provider_msg ON messages (org_id, provider_id, provider_msg_id)
    WHERE provider_msg_id IS NOT NULL;
