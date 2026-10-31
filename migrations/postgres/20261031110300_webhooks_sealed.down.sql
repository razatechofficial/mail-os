ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS delivered_at, DROP COLUMN IF EXISTS message_id;
ALTER TABLE webhooks DROP COLUMN IF EXISTS updated_by, DROP COLUMN IF EXISTS created_by;
-- secret stays TEXT: narrowing could truncate sealed values.
