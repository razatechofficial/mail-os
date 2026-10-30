CREATE TABLE contacts (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_contacts_org_email ON contacts(org_id, email) WHERE deleted_at IS NULL;
CREATE INDEX idx_contacts_org_id ON contacts(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_contacts_org_status ON contacts(org_id, status) WHERE deleted_at IS NULL;
