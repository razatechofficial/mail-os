CREATE TABLE template_versions (
    id VARCHAR(36) PRIMARY KEY,
    template_id VARCHAR(36) NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    version INT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT NOT NULL,
    text_body TEXT,
    variables TEXT[] DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_template_versions_tid_version ON template_versions(template_id, version);
CREATE INDEX idx_template_versions_template_id ON template_versions(template_id);
CREATE INDEX idx_template_versions_active ON template_versions(template_id, is_active) WHERE is_active = true;
