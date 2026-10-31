-- Applications: the projects that send through MailOS (Postmark servers,
-- SES tenants, SendGrid subusers). Each belongs to one tenant and is bound
-- to the IAM OAuth client its owner registered in IAM; MailOS issues no
-- secret or key of its own. A client is one application, platform-wide.
CREATE TABLE IF NOT EXISTS applications (
    id                       VARCHAR(36)  PRIMARY KEY,
    org_id                   VARCHAR(36)  NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name                     VARCHAR(100) NOT NULL,
    description              TEXT         NOT NULL DEFAULT '',
    kind                     VARCHAR(16)  NOT NULL,
    client_id                VARCHAR(255) NOT NULL,
    status                   VARCHAR(16)  NOT NULL DEFAULT 'active',
    suspended_reason         TEXT         NOT NULL DEFAULT '',
    environment              VARCHAR(16)  NOT NULL DEFAULT 'sandbox',
    stream                   VARCHAR(16)  NOT NULL DEFAULT 'transactional',
    message_types            TEXT[]       NOT NULL DEFAULT '{}',
    senders                  TEXT[]       NOT NULL DEFAULT '{}',
    default_from_email       VARCHAR(255) NOT NULL DEFAULT '',
    default_from_name        VARCHAR(255) NOT NULL DEFAULT '',
    default_reply_to         VARCHAR(255) NOT NULL DEFAULT '',
    rate_limit_per_minute    INT          NOT NULL DEFAULT 0,
    daily_quota              INT          NOT NULL DEFAULT 0,
    browser_templates        TEXT[]       NOT NULL DEFAULT '{}',
    user_rate_limit_per_hour INT          NOT NULL DEFAULT 0,
    allowed_origins          TEXT[]       NOT NULL DEFAULT '{}',
    system                   BOOLEAN      NOT NULL DEFAULT false,
    created_by               VARCHAR(255) NOT NULL DEFAULT '',
    updated_by               VARCHAR(255) NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT applications_kind_chk CHECK (kind IN ('server', 'spa')),
    CONSTRAINT applications_status_chk CHECK (status IN ('active', 'suspended')),
    CONSTRAINT applications_environment_chk CHECK (environment IN ('sandbox', 'live')),
    CONSTRAINT applications_stream_chk CHECK (stream IN ('transactional', 'broadcast'))
);

CREATE UNIQUE INDEX IF NOT EXISTS applications_client_id_idx ON applications (client_id);
CREATE UNIQUE INDEX IF NOT EXISTS applications_org_name_idx ON applications (org_id, lower(name));
