-- Evidence of sending (ADR 0001 §3.14 class (a); ETO 2002 s.6): one
-- HMAC-SHA-256 each of the subject, text and HTML a provider was handed,
-- under a key-manager evidence key, with that key's id:
-- {"alg", "kid", "subject", "text", "html"}. Keyed, never a bare hash: the
-- redacted copy and a bare hash would give away a 6-digit code to anyone
-- reading the row. Not content, so the retention purge keeps it.
ALTER TABLE encryption_keys DROP CONSTRAINT encryption_keys_purpose_chk;
ALTER TABLE encryption_keys ADD CONSTRAINT encryption_keys_purpose_chk
    CHECK (purpose IN ('provider', 'dkim', 'webhook', 'message_secret', 'evidence'));

ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_digest JSONB;
CREATE INDEX IF NOT EXISTS messages_sent_digest_kid_idx ON messages ((sent_digest->>'kid')) WHERE sent_digest IS NOT NULL;
