-- Audit events in IAM's format (contract §6), so the bank's SIEM reads
-- MailOS and IAM events alike. The old audit_logs table is left in place
-- and no longer written.
CREATE TABLE IF NOT EXISTS audit_events (
    event_id          UUID PRIMARY KEY,
    service           TEXT NOT NULL DEFAULT 'mailos',
    tier              TEXT NOT NULL,
    severity          SMALLINT NOT NULL,
    actor_uuid        UUID,
    actor_type        TEXT NOT NULL,
    tenant_uuid       UUID,
    organization_uuid UUID,
    resource_type     TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    action            TEXT NOT NULL,
    ip_address        INET,
    user_agent        TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_events_tier_chk CHECK (tier IN ('critical', 'activity')),
    CONSTRAINT audit_events_severity_chk CHECK (severity BETWEEN 0 AND 7),
    CONSTRAINT audit_events_actor_type_chk CHECK (actor_type IN ('user', 'service', 'system'))
);

CREATE INDEX IF NOT EXISTS audit_events_tenant_idx ON audit_events (tenant_uuid, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events (action, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events (created_at);

-- Durable publish queue for FEATURE_AUDIT_STREAM: the event and its outbox
-- row commit together, and the relay publishes to Kafka (IAM's
-- audit_kafka_outbox pattern).
CREATE TABLE IF NOT EXISTS audit_outbox (
    event_id        UUID PRIMARY KEY REFERENCES audit_events (event_id) ON DELETE CASCADE,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempt_count   INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    CONSTRAINT audit_outbox_status_chk CHECK (status IN ('pending', 'published'))
);

CREATE INDEX IF NOT EXISTS audit_outbox_pending_idx ON audit_outbox (next_attempt_at) WHERE status = 'pending';
