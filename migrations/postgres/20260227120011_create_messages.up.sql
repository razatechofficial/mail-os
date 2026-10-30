CREATE TABLE messages (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    campaign_id VARCHAR(36) REFERENCES campaigns(id) ON DELETE SET NULL,
    provider_id VARCHAR(36) REFERENCES providers(id) ON DELETE SET NULL,
    from_name VARCHAR(255) NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    to_name VARCHAR(255),
    subject TEXT NOT NULL,
    html_body TEXT,
    text_body TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'transactional',
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INT NOT NULL DEFAULT 5,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    idempotency_key VARCHAR(255),
    provider_msg_id VARCHAR(255),
    attempts INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    opened_at TIMESTAMPTZ,
    clicked_at TIMESTAMPTZ,
    bounced_at TIMESTAMPTZ,
    scheduled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_messages_org_id ON messages(org_id);
CREATE INDEX idx_messages_org_status ON messages(org_id, status);
CREATE INDEX idx_messages_campaign_id ON messages(campaign_id) WHERE campaign_id IS NOT NULL;
CREATE UNIQUE INDEX idx_messages_idempotency ON messages(org_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_messages_scheduled ON messages(scheduled_at) WHERE status = 'scheduled' AND scheduled_at IS NOT NULL;
CREATE INDEX idx_messages_created_at ON messages(created_at);
