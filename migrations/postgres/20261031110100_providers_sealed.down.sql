ALTER TABLE providers DROP CONSTRAINT IF EXISTS providers_credentials_sealed_chk;
ALTER TABLE providers
    DROP COLUMN IF EXISTS updated_by,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS credential_hints,
    DROP COLUMN IF EXISTS has_credentials,
    DROP COLUMN IF EXISTS credentials_sealed;
