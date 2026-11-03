-- SMTP submission (transport/smtp): legacy applications that can only
-- send over SMTP submit through MailOS under their application's rules.
--
-- applications.smtp_password_auth opts one server application in to
-- MailOS-issued SMTP credentials, the single exception to "MailOS issues no
-- secret" (mailos-applications.md). Without it the application can still
-- submit with an IAM access token (SASL OAUTHBEARER or XOAUTH2).
ALTER TABLE applications ADD COLUMN IF NOT EXISTS smtp_password_auth BOOLEAN NOT NULL DEFAULT false;

-- An application's SMTP credentials. The password is shown once and kept
-- only as an Argon2id hash (PHC string). Revoked credentials stay for the
-- audit trail.
CREATE TABLE IF NOT EXISTS smtp_credentials (
    id             VARCHAR(36)  PRIMARY KEY,
    org_id         VARCHAR(36)  NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    application_id VARCHAR(36)  NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    username       VARCHAR(64)  NOT NULL,
    password_hash  TEXT         NOT NULL,
    description    VARCHAR(200) NOT NULL DEFAULT '',
    created_by     VARCHAR(255) NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rotated_at     TIMESTAMPTZ,
    rotated_by     VARCHAR(255) NOT NULL DEFAULT '',
    last_used_at   TIMESTAMPTZ,
    last_used_ip   VARCHAR(64)  NOT NULL DEFAULT '',
    revoked_at     TIMESTAMPTZ,
    revoked_by     VARCHAR(255) NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS smtp_credentials_username_idx ON smtp_credentials (username);
CREATE INDEX IF NOT EXISTS smtp_credentials_application_idx ON smtp_credentials (org_id, application_id);

-- Headers a submission carries through to the provider: today only
-- List-Unsubscribe and List-Unsubscribe-Post (RFC 2369, RFC 8058), which
-- broadcast mail needs.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS headers JSONB;
