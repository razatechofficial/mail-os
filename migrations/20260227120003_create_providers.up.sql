CREATE TABLE providers (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL,
    configuration JSONB NOT NULL DEFAULT '{}',
    priority INT NOT NULL DEFAULT 0,
    weight INT NOT NULL DEFAULT 100,
    daily_limit INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX idx_providers_org_id ON providers(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_providers_org_active ON providers(org_id, is_active) WHERE deleted_at IS NULL;
