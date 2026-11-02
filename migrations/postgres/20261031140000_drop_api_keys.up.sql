-- api_keys belonged to the removed API-key authentication: every caller now
-- presents an IAM access token, and no code reads or writes this table.
DROP TABLE IF EXISTS api_keys;
