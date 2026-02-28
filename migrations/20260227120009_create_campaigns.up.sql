CREATE TABLE campaigns (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    from_name VARCHAR(255) NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    template_id VARCHAR(36) REFERENCES templates(id) ON DELETE SET NULL,
    contact_list_id VARCHAR(36) REFERENCES contact_lists(id) ON DELETE SET NULL,
    type VARCHAR(20) NOT NULL DEFAULT 'regular',
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    total_recipients INT NOT NULL DEFAULT 0,
    sent_count INT NOT NULL DEFAULT 0,
    failed_count INT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX idx_campaigns_org_id ON campaigns(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_campaigns_org_status ON campaigns(org_id, status) WHERE deleted_at IS NULL;
