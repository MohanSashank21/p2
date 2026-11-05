CREATE TABLE IF NOT EXISTS contact_test_submissions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  marker TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  service_version TEXT NOT NULL,
  vcs_revision TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
