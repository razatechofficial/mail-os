CREATE TABLE suppressions (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL,
    reason TEXT,
    source VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_suppressions_org_email ON suppressions(org_id, email);
CREATE INDEX idx_suppressions_org_id ON suppressions(org_id);
CREATE INDEX idx_suppressions_org_type ON suppressions(org_id, type);
