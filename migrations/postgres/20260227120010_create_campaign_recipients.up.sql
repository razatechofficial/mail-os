CREATE TABLE campaign_recipients (
    campaign_id VARCHAR(36) NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    contact_id VARCHAR(36) NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    sent_at TIMESTAMPTZ,
    error TEXT,
    PRIMARY KEY (campaign_id, contact_id)
);
CREATE INDEX idx_campaign_recipients_campaign_status ON campaign_recipients(campaign_id, status);
