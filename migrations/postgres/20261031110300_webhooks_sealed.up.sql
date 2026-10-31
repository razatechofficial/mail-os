-- Webhook signing secrets are sealed in place (purpose "webhook"): the
-- column widens to hold km1 values, and the startup conversion seals any
-- plaintext secret still there. Deliveries record the message they are
-- about.
ALTER TABLE webhooks ALTER COLUMN secret TYPE TEXT;
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255);
ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS message_id   VARCHAR(36),
    ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;
