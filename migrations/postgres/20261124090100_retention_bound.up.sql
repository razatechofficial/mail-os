-- Message retention is bounded at 90 days (ADR 0001 §3.6): a tenant's own
-- setting above it is lowered to it, and the bound is enforced here too.
UPDATE tenant_settings SET message_retention_days = 90, updated_at = now() WHERE message_retention_days > 90;
ALTER TABLE tenant_settings DROP CONSTRAINT tenant_settings_retention_chk;
ALTER TABLE tenant_settings ADD CONSTRAINT tenant_settings_retention_chk
    CHECK (message_retention_days IS NULL OR message_retention_days BETWEEN 1 AND 90);
