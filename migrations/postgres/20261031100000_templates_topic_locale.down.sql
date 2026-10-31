DROP INDEX IF EXISTS idx_templates_org_topic;
ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_default_locale_chk;
ALTER TABLE templates
    DROP COLUMN IF EXISTS default_locale,
    DROP COLUMN IF EXISTS topic;
