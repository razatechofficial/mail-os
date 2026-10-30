CREATE TABLE message_events (
    id VARCHAR(36) PRIMARY KEY,
    message_id VARCHAR(36) NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL,
    provider VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_message_events_message_id ON message_events(message_id);
CREATE INDEX idx_message_events_org_id ON message_events(org_id);
CREATE INDEX idx_message_events_org_type ON message_events(org_id, type);
CREATE INDEX idx_message_events_created_at ON message_events(created_at);
