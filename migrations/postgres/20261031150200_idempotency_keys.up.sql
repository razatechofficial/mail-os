-- Idempotency-Key on POST /messages/send and /messages/batch: the first
-- response for (scope, key) is kept until expires_at and replayed for the
-- same request; the same key with another body is refused. scope is the
-- application id, or "tenant:<id>" for a console user's send.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope          VARCHAR(80)  NOT NULL,
    key            VARCHAR(255) NOT NULL,
    request_sha256 VARCHAR(64)  NOT NULL,
    status_code    INT          NOT NULL DEFAULT 0,
    response       BYTEA,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (scope, key)
);
CREATE INDEX IF NOT EXISTS idempotency_keys_expires_idx ON idempotency_keys (expires_at);
