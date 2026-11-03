ALTER TABLE messages DROP COLUMN IF EXISTS headers;
DROP TABLE IF EXISTS smtp_credentials;
ALTER TABLE applications DROP COLUMN IF EXISTS smtp_password_auth;
