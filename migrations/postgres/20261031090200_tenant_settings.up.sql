-- A MailOS tenant is an IAM tenant: organizations.id holds the IAM tenant
-- UUID, provisioned on the tenant's first verified request. Its security
-- settings live here.
CREATE TABLE IF NOT EXISTS tenant_settings (
    org_id                 VARCHAR(36) PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    four_eyes_publish      BOOLEAN NOT NULL DEFAULT false,
    message_retention_days INT,
    updated_by             TEXT,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tenant_settings_retention_chk CHECK (message_retention_days IS NULL OR message_retention_days BETWEEN 1 AND 3650)
);
