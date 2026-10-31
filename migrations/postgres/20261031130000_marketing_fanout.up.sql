-- Campaign fan-out: each recipient row is claimed (queued) before the
-- message is handed to the messaging slice, then records the message it
-- became. The partial indexes serve the release task: scheduled campaigns
-- that are due, and sending campaigns whose fan-out stalled.
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS message_id VARCHAR(64);
ALTER TABLE campaign_recipients ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_campaigns_due ON campaigns (scheduled_at)
    WHERE status = 'scheduled' AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_campaigns_sending ON campaigns (updated_at)
    WHERE status = 'sending' AND deleted_at IS NULL;
