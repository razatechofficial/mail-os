#!/bin/bash
# The stack's one Postgres: the IAM's database (iam, owned by the superuser
# as the IAM's e2e runner expects), ACS's (acs: acs_migrate owns it,
# acs_app runs, acs_applier writes the schema), SpiceDB's datastore (shared
# by the IAM and ACS, as in production) and MailOS's (mail_os).
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v migrate_pw="$ACS_MIGRATE_PASSWORD" -v app_pw="$ACS_APP_PASSWORD" -v applier_pw="$ACS_APPLIER_PASSWORD" \
  -v spicedb_pw="$SPICEDB_DB_PASSWORD" <<'SQL'
CREATE DATABASE iam;
CREATE DATABASE mail_os;
CREATE ROLE acs_migrate LOGIN PASSWORD :'migrate_pw';
CREATE ROLE acs_app LOGIN PASSWORD :'app_pw';
CREATE ROLE acs_applier LOGIN PASSWORD :'applier_pw';
CREATE ROLE spicedb LOGIN PASSWORD :'spicedb_pw';
CREATE DATABASE acs OWNER acs_migrate;
CREATE DATABASE spicedb OWNER spicedb;
REVOKE ALL ON DATABASE acs FROM PUBLIC;
REVOKE ALL ON DATABASE spicedb FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE acs TO acs_app;
GRANT CONNECT ON DATABASE acs TO acs_applier;
\connect acs
ALTER DEFAULT PRIVILEGES FOR ROLE acs_migrate IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO acs_app;
ALTER DEFAULT PRIVILEGES FOR ROLE acs_migrate IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO acs_app;
SQL
