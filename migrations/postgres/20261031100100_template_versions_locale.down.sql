DROP INDEX IF EXISTS idx_template_versions_active_locale;
ALTER TABLE template_versions
    DROP CONSTRAINT IF EXISTS template_versions_status_chk,
    DROP CONSTRAINT IF EXISTS template_versions_locale_chk;
ALTER TABLE template_versions
    DROP COLUMN IF EXISTS published_at,
    DROP COLUMN IF EXISTS published_by,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS design,
    DROP COLUMN IF EXISTS preheader,
    DROP COLUMN IF EXISTS locale;
