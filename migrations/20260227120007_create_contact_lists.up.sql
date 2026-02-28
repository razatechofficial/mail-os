CREATE TABLE contact_lists (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'static',
    query TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX idx_contact_lists_org_id ON contact_lists(org_id) WHERE deleted_at IS NULL;
