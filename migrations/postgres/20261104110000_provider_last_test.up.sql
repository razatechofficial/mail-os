-- The outcome of a provider's last connection test or test send, for the
-- console: kind, ok, time, failed step, error class, detail and hint. It
-- never holds a secret.
ALTER TABLE providers ADD COLUMN IF NOT EXISTS last_test JSONB;
