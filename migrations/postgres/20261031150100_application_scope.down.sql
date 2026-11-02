DROP INDEX IF EXISTS idx_suppressions_org_email_scope;
DELETE FROM suppressions WHERE application_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_suppressions_org_email ON suppressions (org_id, email);
ALTER TABLE suppressions DROP COLUMN IF EXISTS application_id;

DROP INDEX IF EXISTS idx_webhooks_application;
ALTER TABLE webhooks DROP COLUMN IF EXISTS application_id;

ALTER TABLE inbound_events DROP COLUMN IF EXISTS application_id;

DROP INDEX IF EXISTS idx_messages_application_created;
ALTER TABLE messages
    DROP COLUMN IF EXISTS stream,
    DROP COLUMN IF EXISTS sandbox,
    DROP COLUMN IF EXISTS application_id;
