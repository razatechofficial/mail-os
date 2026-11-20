-- Live secrets of authentication-class messages (ADR 0001 §3.6): the
-- one-time codes and token-bearing links a message's stored copy holds only
-- as redaction descriptors. Each row is sealed by the key manager (purpose
-- message_secret), read only by the worker's delivery path for a retry, and
-- deleted when the message reaches a final status or at expires_at, which
-- is never more than an hour after it was stored.
ALTER TABLE encryption_keys DROP CONSTRAINT encryption_keys_purpose_chk;
ALTER TABLE encryption_keys ADD CONSTRAINT encryption_keys_purpose_chk
    CHECK (purpose IN ('provider', 'dkim', 'webhook', 'message_secret'));

CREATE TABLE IF NOT EXISTS message_secrets (
    message_id VARCHAR(36) PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE,
    org_id     VARCHAR(36) NOT NULL,
    sealed     TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT message_secrets_ttl_chk CHECK (expires_at <= created_at + interval '1 hour')
);
CREATE INDEX IF NOT EXISTS message_secrets_expires_idx ON message_secrets (expires_at);
