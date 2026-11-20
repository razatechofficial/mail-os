ALTER TABLE tenant_settings DROP CONSTRAINT tenant_settings_retention_chk;
ALTER TABLE tenant_settings ADD CONSTRAINT tenant_settings_retention_chk
    CHECK (message_retention_days IS NULL OR message_retention_days BETWEEN 1 AND 3650);
