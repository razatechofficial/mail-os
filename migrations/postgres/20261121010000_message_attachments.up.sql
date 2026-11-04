-- The files a message carries (send API and SMTP relay): attachments and
-- inline parts by Content-ID. They are personal data like the bodies and
-- are erased with them by the retention purge; deleting the message
-- deletes them.
CREATE TABLE IF NOT EXISTS message_attachments (
    message_id   VARCHAR(36)  NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
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
    PRIMARY KEY (message_id, position)
);
