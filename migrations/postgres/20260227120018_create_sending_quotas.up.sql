CREATE TABLE sending_quotas (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    daily_limit INT NOT NULL DEFAULT 10000,
    daily_used INT NOT NULL DEFAULT 0,
    monthly_limit INT NOT NULL DEFAULT 300000,
    monthly_used INT NOT NULL DEFAULT 0,
    reset_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_sending_quotas_org_id ON sending_quotas(org_id);
