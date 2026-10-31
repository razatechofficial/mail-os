DROP INDEX IF EXISTS idx_campaigns_sending;
DROP INDEX IF EXISTS idx_campaigns_due;
ALTER TABLE campaign_recipients DROP COLUMN IF EXISTS claimed_at;
ALTER TABLE campaign_recipients DROP COLUMN IF EXISTS message_id;
