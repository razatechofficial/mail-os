-- DKIM private keys are sealed (purpose "dkim"); the plaintext
-- dkim_private_key column is no longer written and the startup conversion
-- empties it.
ALTER TABLE sending_domains
    ADD COLUMN IF NOT EXISTS dkim_selector           VARCHAR(63),
    ADD COLUMN IF NOT EXISTS dkim_private_key_sealed TEXT,
    ADD COLUMN IF NOT EXISTS last_checked_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS failure_reason          TEXT,
    ADD COLUMN IF NOT EXISTS created_by              VARCHAR(255);

ALTER TABLE sending_domains DROP CONSTRAINT IF EXISTS sending_domains_dkim_sealed_chk;
ALTER TABLE sending_domains ADD CONSTRAINT sending_domains_dkim_sealed_chk
    CHECK (dkim_private_key_sealed IS NULL OR dkim_private_key_sealed LIKE 'km1.%') NOT VALID;
