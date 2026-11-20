DROP TABLE IF EXISTS message_secrets;
DELETE FROM encryption_keys WHERE purpose = 'message_secret';
ALTER TABLE encryption_keys DROP CONSTRAINT encryption_keys_purpose_chk;
ALTER TABLE encryption_keys ADD CONSTRAINT encryption_keys_purpose_chk
    CHECK (purpose IN ('provider', 'dkim', 'webhook'));
