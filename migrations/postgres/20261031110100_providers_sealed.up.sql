-- Provider credentials are sealed by the key manager (km1 values, purpose
-- "provider"); configuration keeps only the non-secret settings. The
-- startup conversion moves any plaintext secret out of configuration.
ALTER TABLE providers
    ADD COLUMN IF NOT EXISTS credentials_sealed TEXT,
    ADD COLUMN IF NOT EXISTS has_credentials    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS credential_hints   JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS created_by         VARCHAR(255),
    ADD COLUMN IF NOT EXISTS updated_by         VARCHAR(255);

ALTER TABLE providers DROP CONSTRAINT IF EXISTS providers_credentials_sealed_chk;
ALTER TABLE providers ADD CONSTRAINT providers_credentials_sealed_chk
    CHECK (credentials_sealed IS NULL OR credentials_sealed LIKE 'km1.%') NOT VALID;
