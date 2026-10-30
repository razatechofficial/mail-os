CREATE TABLE templates (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    category VARCHAR(20) NOT NULL DEFAULT 'transactional',
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_templates_org_slug ON templates(org_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_templates_org_id ON templates(org_id) WHERE deleted_at IS NULL;
