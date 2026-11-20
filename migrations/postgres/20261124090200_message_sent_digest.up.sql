-- Evidence of sending (ADR 0001 §3.6; ETO 2002 s.6): the keyed digest of
-- the subject, text and HTML a provider was handed. With the template
-- version and the stored redacted data it shows what was sent without
-- keeping the one-time code or link. It is not content, so the retention
-- purge keeps it with the envelope.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_digest TEXT;
