-- Events received from services (HTTP, gRPC, Kafka), one row per tenant and
-- event id, so a redelivered event is accepted without a second message.
-- The data is not stored: only its hash, to tell a redelivery from another
-- event reusing the id.
CREATE TABLE IF NOT EXISTS inbound_events (
    org_id      VARCHAR(36)  NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    event_id    VARCHAR(128) NOT NULL,
    topic       VARCHAR(128) NOT NULL,
    client_id   TEXT         NOT NULL,
    transport   VARCHAR(16)  NOT NULL,
    data_sha256 CHAR(64)     NOT NULL,
    message_id  TEXT,
    received_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, event_id),
    CONSTRAINT inbound_events_transport_chk CHECK (transport IN ('http', 'grpc', 'kafka'))
);

CREATE INDEX IF NOT EXISTS inbound_events_received_idx ON inbound_events (received_at);
