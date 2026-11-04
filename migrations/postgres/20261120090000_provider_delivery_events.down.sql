DROP INDEX IF EXISTS idx_messages_provider_msg;
DROP INDEX IF EXISTS uq_message_events_key;
ALTER TABLE message_events
    DROP COLUMN IF EXISTS occurred_at,
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS event_key,
    DROP COLUMN IF EXISTS provider_id;
