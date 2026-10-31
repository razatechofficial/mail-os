-- Published versions are per locale and immutable; one is active per
-- template and locale. Rows from before carry locale 'en'.
ALTER TABLE template_versions
    ADD COLUMN IF NOT EXISTS locale       VARCHAR(8)  NOT NULL DEFAULT 'en',
    ADD COLUMN IF NOT EXISTS preheader    TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS design       JSONB,
    ADD COLUMN IF NOT EXISTS status       VARCHAR(16) NOT NULL DEFAULT 'published',
    ADD COLUMN IF NOT EXISTS published_by TEXT,
    ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;

ALTER TABLE template_versions
    ADD CONSTRAINT template_versions_locale_chk CHECK (locale IN ('en', 'ur')),
    ADD CONSTRAINT template_versions_status_chk CHECK (status IN ('published'));

UPDATE template_versions SET published_at = created_at WHERE published_at IS NULL;

-- The old code marked every new version active without deactivating the
-- others; keep the newest active per template and locale.
UPDATE template_versions v SET is_active = false
WHERE v.is_active AND EXISTS (
    SELECT 1 FROM template_versions w
    WHERE w.template_id = v.template_id AND w.locale = v.locale AND w.is_active AND w.version > v.version);

CREATE UNIQUE INDEX IF NOT EXISTS idx_template_versions_active_locale
    ON template_versions (template_id, locale) WHERE is_active;
