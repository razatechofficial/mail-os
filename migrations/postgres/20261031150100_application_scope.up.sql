-- What each application sent and received: messages, events, webhooks and
-- suppressions carry the application they belong to. NULL is the tenant
-- itself (console sends, campaigns, tenant-wide webhooks and suppressions).
-- Messages also record the sandbox flag and the stream they went out on.
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS application_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS sandbox        BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS stream         VARCHAR(16) NOT NULL DEFAULT 'transactional';
CREATE INDEX IF NOT EXISTS idx_messages_application_created ON messages (application_id, created_at DESC)
    WHERE application_id IS NOT NULL;

ALTER TABLE inbound_events ADD COLUMN IF NOT EXISTS application_id VARCHAR(36);

ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS application_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS idx_webhooks_application ON webhooks (application_id) WHERE deleted_at IS NULL;

-- A suppression is tenant-wide (application_id NULL, applies to every
-- application) or scoped to one application; an address is listed once
-- per scope.
ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS application_id VARCHAR(36);
DROP INDEX IF EXISTS idx_suppressions_org_email;
CREATE UNIQUE INDEX IF NOT EXISTS idx_suppressions_org_email_scope ON suppressions (org_id, email, COALESCE(application_id, ''));
