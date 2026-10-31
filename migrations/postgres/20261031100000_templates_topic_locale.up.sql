-- A template names the event topic it serves and the locale a send falls
-- back to (docs/mailos-template-api.md, Storage). One live template per
-- topic in an organization, so an event resolves to one template.
ALTER TABLE templates
    ADD COLUMN IF NOT EXISTS topic          VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS default_locale VARCHAR(8)   NOT NULL DEFAULT 'en';

ALTER TABLE templates
    ADD CONSTRAINT templates_default_locale_chk CHECK (default_locale IN ('en', 'ur'));

CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_org_topic
    ON templates (org_id, topic) WHERE topic <> '' AND deleted_at IS NULL;
