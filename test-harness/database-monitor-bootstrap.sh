#!/bin/sh
set -eu

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_EXPORTER_PASSWORD:?POSTGRES_EXPORTER_PASSWORD is required}"

psql \
  --host=database \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=exporter_password="$POSTGRES_EXPORTER_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE portfolio_monitor LOGIN PASSWORD %L', :'exporter_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portfolio_monitor')
\gexec
SELECT format('ALTER ROLE portfolio_monitor LOGIN PASSWORD %L', :'exporter_password')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portfolio_monitor')
\gexec
GRANT pg_monitor TO portfolio_monitor;
ALTER TABLE contact_test_submissions
  ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT 'legacy',
  ADD COLUMN IF NOT EXISTS service_version TEXT NOT NULL DEFAULT 'legacy',
  ADD COLUMN IF NOT EXISTS vcs_revision TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS trace_id TEXT NOT NULL DEFAULT '';
GRANT CONNECT ON DATABASE portfolio_test TO portfolio_monitor;
GRANT USAGE ON SCHEMA public TO portfolio_monitor;
GRANT SELECT ON contact_test_submissions TO portfolio_monitor;
SQL
