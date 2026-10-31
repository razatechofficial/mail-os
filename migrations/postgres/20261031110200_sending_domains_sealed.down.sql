ALTER TABLE sending_domains DROP CONSTRAINT IF EXISTS sending_domains_dkim_sealed_chk;
ALTER TABLE sending_domains
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS failure_reason,
    DROP COLUMN IF EXISTS last_checked_at,
    DROP COLUMN IF EXISTS dkim_private_key_sealed,
    DROP COLUMN IF EXISTS dkim_selector;
