-- A template's work in progress, one per locale. revision counts saves; a
-- save naming another revision is refused (409).
CREATE TABLE IF NOT EXISTS template_drafts (
    template_id VARCHAR(36) NOT NULL REFERENCES templates (id) ON DELETE CASCADE,
    locale      VARCHAR(8)  NOT NULL,
    subject     TEXT        NOT NULL,
    preheader   TEXT        NOT NULL DEFAULT '',
    design      JSONB,
    html_body   TEXT        NOT NULL,
    text_body   TEXT        NOT NULL,
    variables   TEXT[]      NOT NULL DEFAULT '{}',
    revision    INT         NOT NULL,
    updated_by  TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (template_id, locale),
    CONSTRAINT template_drafts_locale_chk CHECK (locale IN ('en', 'ur')),
    CONSTRAINT template_drafts_revision_chk CHECK (revision > 0)
);
