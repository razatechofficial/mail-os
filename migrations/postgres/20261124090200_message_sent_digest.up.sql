-- Evidence of sending (ADR 0001 §3.14 class (a); ETO 2002 s.6): one keyed
-- SHA-256 (HMAC) each of the subject, text and HTML a provider was handed,
-- with the key's id: {"alg", "kid", "subject", "text", "html"}. With the template
-- version and the stored redacted data it shows what was sent without
-- keeping the one-time code or link. It is not content, so the retention
-- purge keeps it with the envelope.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_digest JSONB;
