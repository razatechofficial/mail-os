ALTER TABLE suppressions DROP COLUMN IF EXISTS created_by;
DROP INDEX IF EXISTS idx_messages_provider_sent;
DROP INDEX IF EXISTS idx_messages_pending;
DROP INDEX IF EXISTS idx_messages_purge;
DROP INDEX IF EXISTS idx_messages_org_created;
ALTER TABLE messages
    DROP COLUMN IF EXISTS body_purged_at,
    DROP COLUMN IF EXISTS cancelled_at,
    DROP COLUMN IF EXISTS failed_at,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS actor_id,
    DROP COLUMN IF EXISTS actor_type,
    DROP COLUMN IF EXISTS event_id,
    DROP COLUMN IF EXISTS secret_keys,
    DROP COLUMN IF EXISTS template_data,
    DROP COLUMN IF EXISTS locale,
    DROP COLUMN IF EXISTS template_version_id,
    DROP COLUMN IF EXISTS template_id,
    DROP COLUMN IF EXISTS source,
    DROP COLUMN IF EXISTS topic,
    DROP COLUMN IF EXISTS reply_to;
