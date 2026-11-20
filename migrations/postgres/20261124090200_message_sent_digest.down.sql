DROP INDEX IF EXISTS messages_sent_digest_kid_idx;
ALTER TABLE messages DROP COLUMN IF EXISTS sent_digest;
DELETE FROM encryption_keys WHERE purpose = 'evidence';
ALTER TABLE encryption_keys DROP CONSTRAINT encryption_keys_purpose_chk;
ALTER TABLE encryption_keys ADD CONSTRAINT encryption_keys_purpose_chk
    CHECK (purpose IN ('provider', 'dkim', 'webhook', 'message_secret'));
