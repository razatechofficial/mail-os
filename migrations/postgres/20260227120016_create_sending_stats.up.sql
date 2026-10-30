CREATE TABLE sending_stats (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    period_type VARCHAR(10) NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    sent INT NOT NULL DEFAULT 0,
    delivered INT NOT NULL DEFAULT 0,
    bounced INT NOT NULL DEFAULT 0,
    complained INT NOT NULL DEFAULT 0,
    opened INT NOT NULL DEFAULT 0,
    clicked INT NOT NULL DEFAULT 0,
    failed INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_sending_stats_org_period ON sending_stats(org_id, period_type, period_start);
CREATE INDEX idx_sending_stats_org_id ON sending_stats(org_id);
