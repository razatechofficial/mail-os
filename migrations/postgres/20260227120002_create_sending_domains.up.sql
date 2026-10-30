CREATE TABLE sending_domains (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    dkim_public_key TEXT,
    dkim_private_key TEXT,
    spf_record TEXT,
    dmarc_record TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_sending_domains_org_domain ON sending_domains(org_id, domain) WHERE deleted_at IS NULL;
CREATE INDEX idx_sending_domains_org_id ON sending_domains(org_id) WHERE deleted_at IS NULL;
