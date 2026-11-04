-- The files a campaign sends to every recipient, checked against the
-- attachment limits and scanned when the campaign is saved. Each message
-- the fan-out queues stores its own copy in message_attachments, so the
-- retention purge of messages never touches these.
CREATE TABLE IF NOT EXISTS campaign_attachments (
    campaign_id  VARCHAR(36)  NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    position     SMALLINT     NOT NULL,
    org_id       VARCHAR(36)  NOT NULL,
    filename     VARCHAR(255) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    content_id   VARCHAR(255),
    inline       BOOLEAN      NOT NULL DEFAULT false,
    size_bytes   INTEGER      NOT NULL CHECK (size_bytes > 0),
    sha256       CHAR(64)     NOT NULL,
    data         BYTEA        NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (campaign_id, position)
);
