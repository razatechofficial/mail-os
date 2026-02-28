CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    prefix VARCHAR(8) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX idx_api_keys_org_id ON api_keys(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix) WHERE deleted_at IS NULL AND is_active = true;
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash) WHERE deleted_at IS NULL AND is_active = true;
