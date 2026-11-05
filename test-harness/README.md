# OpsPilot live test harness

This opt-in harness adds a local API beside the existing static Portfolio site.
The existing EmailJS contact flow is unchanged. The harness uses a fixed
synthetic marker and a local PostgreSQL database; it never sends email or uses
real contact details.

The test failure is a real database connection failure: stop the harness
database, submit the synthetic request, and the API returns `503`. The same
request produces an OpenTelemetry error span, a Prometheus counter increment,
a PostgreSQL exporter `pg_up` signal, a Loki log entry, and Docker container
evidence. The test trace, API response, successful database rows, structured
logs, Prometheus build-info metric, and Docker labels all carry the same
deployment ID, service version, and VCS revision. A manually-run GitHub
Actions check can make the same request while the database is stopped and
fail on the actual `503` response.

## 1. Start the isolated local services

From the Portfolio repository root:

```bash
cp test-harness/.env.example test-harness/.env
python - <<'PY'
from pathlib import Path
import secrets

env_file = Path("test-harness/.env")
lines = env_file.read_text().splitlines()
key = "OPSPILOT_TEST_TOKEN="
matches = [index for index, line in enumerate(lines) if line.startswith(key)]
if len(matches) != 1:
    raise SystemExit("Expected exactly one OPSPILOT_TEST_TOKEN entry in .env")

lines[matches[0]] = key + secrets.token_urlsafe(32)
env_file.write_text("\n".join(lines) + "\n")
env_file.chmod(0o600)
print("Generated OPSPILOT_TEST_TOKEN in test-harness/.env (value not displayed).")
PY
```

Run the generator only when first setting up or intentionally rotating the
token; rotation invalidates the previous value. The `.env` file is ignored by
Git. The generator restricts it to the current user on POSIX systems. On
Windows, also restrict its NTFS ACL from PowerShell:

```powershell
icacls test-harness\.env /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(F)"
```

Keep the file local; do not commit it.

Set unique local values for `POSTGRES_PASSWORD`,
`POSTGRES_EXPORTER_PASSWORD`, and `GRAFANA_ADMIN_PASSWORD`. Set
`DEPLOYMENT_ID` to identify this test deployment, `SERVICE_VERSION` to the
test build version, and `VCS_REVISION` to the Portfolio commit under test.
`VCS_REVISION` can be obtained with `git rev-parse HEAD`. Do not put live
credentials in `.env.example` or commit `test-harness/.env`.

Start the harness:

```bash
docker compose --env-file test-harness/.env -f test-harness/docker-compose.yml up --build -d
docker compose --env-file test-harness/.env -f test-harness/docker-compose.yml ps
```

The containers bind to loopback only. Their host ports are:

| Service | Local URL |
|---|---|
| Test API | `http://127.0.0.1:8010` |
| Loki | `http://127.0.0.1:3101` |
| Tempo | `http://127.0.0.1:3201` |
| Tempo OTLP/HTTP receiver | `http://127.0.0.1:4319` |
| Prometheus | `http://127.0.0.1:9091` |
| Test Grafana | `http://127.0.0.1:3001` |
| PostgreSQL exporter | Internal to the Compose network; not host-published |

Use the `GRAFANA_ADMIN_PASSWORD` from the local `.env` to sign in as `admin`.
The isolated Loki, Tempo, and Prometheus containers do not replace or modify
the other local observability containers.

The test database's `portfolio_monitor` role is separate from the application
user. It is granted PostgreSQL's `pg_monitor` role and `SELECT` on the test
submissions table only. The Compose bootstrap applies its role and schema
changes idempotently, including when the existing local database volume
predates this addition. Keep the exporter un-published; it is intended for
Prometheus inside this private Compose network.

## 2. Enable the button in the existing Portfolio page

In another terminal:

```bash
VITE_OPSPILOT_TEST_HARNESS=true npm run dev -- --host 127.0.0.1
```

Open the Vite URL and scroll to **Portfolio contact-service check**. Enter the
local test token from `test-harness/.env` in the password-style token field
and submit once while the database is running. The response should be HTTP
`201`; this is the healthy baseline.

To invoke the same synthetic request from a terminal without printing or
placing the token in shell history or process arguments, run this Python
snippet from the repository root. It sends a real request and writes one
synthetic test row when PostgreSQL is available:

```bash
python - <<'PY'
import json
from pathlib import Path
from urllib.request import Request, urlopen

env_file = Path("test-harness/.env")
token_line = next(
    line for line in env_file.read_text().splitlines()
    if line.startswith("OPSPILOT_TEST_TOKEN=")
)
token = token_line.partition("=")[2].strip().strip("\"'")
request = Request(
    "http://127.0.0.1:8010/api/test/contact",
    data=json.dumps({"marker": "opspilot-portfolio-live-test"}).encode(),
    headers={
        "Content-Type": "application/json",
        "X-Opspilot-Test-Token": token,
    },
    method="POST",
)
with urlopen(request, timeout=5) as response:
    print(f"HTTP {response.status}")
    print(response.read().decode())
PY
```

The Compose `--env-file test-harness/.env` option supplies the same token to
the API container. Do not use the OpsPilot user access token or Grafana
webhook credential for this endpoint; they serve different authentication
boundaries.

## 3. Connect the sources to one OpsPilot project

Create or enable Docker, Loki, Tempo, Grafana, and the Portfolio GitHub
repository in the **same project** as the incident. The sources cannot be
correlated across separate projects.

For these local endpoints, the OpsPilot server allowlists must include
`localhost:3101` for Loki and `localhost:3201` for Tempo. Configure
`TRACE_ALLOWED_HOSTS` and `LOKI_ALLOWED_HOSTS` in OpsPilot's environment and
restart its API before creating the sources.

Configure the sources as follows:

- Loki URL: `http://localhost:3101`
- Tempo URL: `http://localhost:3201`, backend `tempo`, service name
  `portfolio-api`
- Grafana: use the test Grafana at `http://localhost:3001`
- Docker: use the local Docker daemon
- GitHub: connect `MohanSashank21/Portfolio`

OpsPilot's Docker investigation reads the local Docker daemon. Do not expose a
Docker socket or daemon on a public interface. The temporary tunnels below are
only for the narrowly scoped test HTTP endpoints.

## 4. Set up a Prometheus-backed Grafana alert

The test Grafana already has a Prometheus data source named
**Portfolio Test Prometheus**. In Grafana, create an alert rule with this
query:

```promql
(pg_up{job="postgres-exporter"} == bool 0)
  * on() group_left(deployment_id, service_version, vcs_revision)
    portfolio_build_info
```

Set the condition to alert when the result is above `0.5`, with a 10-second
evaluation interval. This is the PostgreSQL availability signal: the exporter
can still be scraped while `pg_up` reports that it cannot reach PostgreSQL.
Add these labels so the incident evidence can be correlated with Loki:

```text
environment=local
deployment_id=<same value as DEPLOYMENT_ID>
service_version=<same value as SERVICE_VERSION>
vcs_revision=<same value as VCS_REVISION>
ops_pilot_test=true
scenario=portfolio-contact-database-outage
service_name=portfolio-api
```

Add a summary annotation such as `Portfolio test API cannot reach PostgreSQL`.
Attach the rule to a contact point that posts to the Grafana webhook URL for
the Grafana source in the same OpsPilot project:

```text
https://<OPSPILOT-TUNNEL>/webhooks/sources/<GRAFANA-SOURCE-ID>/grafana
```

Set the contact point's `Authorization` header to
`Bearer <GRAFANA-SOURCE-CREDENTIAL>`. A firing notification should create an
incident whose evidence contains the observed PostgreSQL availability,
deployment, and service labels.

Additional PostgreSQL signals to inspect in Prometheus include:

```promql
pg_up{job="postgres-exporter"}
up{job="postgres-exporter"}
pg_stat_database_deadlocks{datname="portfolio_test"}
pg_stat_database_xact_rollback{datname="portfolio_test"}
```

The deadlock and rollback values are cumulative counters; inspect their
`increase(...[5m])` over the incident window rather than interpreting their
absolute values as current rates.

## 5. Prepare GitHub without touching `main`

Review the local changes, then commit and push only this test branch when you
are ready for GitHub Actions:

```bash
git switch opspilot-user-test-harness
git status
git add .github/workflows/opspilot-test-harness.yml src/App.jsx src/components/OpsPilotTestHarness.jsx vite.config.js .gitignore test-harness
git commit -m "Add local OpsPilot integration test harness"
git push -u origin opspilot-user-test-harness
```

In the Portfolio repository's GitHub Actions secrets, add
`OPSPILOT_TEST_TOKEN` with the same value as the local token. The workflow
accepts only an HTTPS Cloudflare quick-tunnel origin and calls the same API
endpoint as the local button.

## 6. Trigger the failure yourself

Start a temporary tunnel to the test API in one terminal:

```bash
cloudflared tunnel --url http://127.0.0.1:8010
```

Copy its HTTPS URL. In a separate terminal, start a temporary tunnel to the
OpsPilot API for GitHub webhook deliveries:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

In the GitHub App settings, temporarily set its webhook URL to the second
tunnel's HTTPS URL followed by `/webhooks/github`. Restore the prior URL after
the test. The webhook signature is still verified by OpsPilot.

Keep the test API tunnel URL private. It exposes only the test API, which
requires the test token; stop the tunnel immediately after the workflow run.

Now, from the Portfolio repository root:

```bash
docker compose --env-file test-harness/.env -f test-harness/docker-compose.yml stop database
```

Submit the test request in the Portfolio page. It should return HTTP `503` and
show `test_database_unavailable` plus a trace ID. Do not use real contact data.

While the database remains stopped, open the GitHub Actions workflow
**OpsPilot Portfolio test request**, choose **Run workflow**, and enter the
first tunnel URL as `api_base_url`. The workflow should fail because the live
API returned `503`, not because of a hard-coded `exit 1`.

The Grafana rule should fire shortly afterward. Verify the signals before
investigating:

- Prometheus: `http://127.0.0.1:9091/graph`, query
  `pg_up{job="postgres-exporter"}` and
  `portfolio_test_database_failures_total`
- Deployment identity: `http://127.0.0.1:8010/metadata` and
  `portfolio_build_info` in Prometheus
- Loki: `http://127.0.0.1:3101/explore`, selector
  `{service_name="portfolio-api", scenario="portfolio-contact-database-outage", deployment_id="<DEPLOYMENT_ID>"}`
- Tempo: search for service `portfolio-api` and inspect the failed request
- Docker: inspect `portfolio-opspilot-test-api`,
  `portfolio-opspilot-test-database`, and
  `portfolio-opspilot-test-postgres-exporter`; compare their
  `com.opspilot.deployment-id` and OCI version/revision labels
- GitHub: confirm the manually-run workflow failed after the API returned
  `503`, and confirm OpsPilot received its completed `workflow_run` event

## 7. Run OpsPilot's combined investigation

Use the incident created by the Grafana alert. Select a bounded trace time
range around the failed request and filter by service `portfolio-api`. Query
Loki with labels that match the incident's Grafana labels. Select the API or
database container ID from `docker ps -a --no-trunc`. Select the failed
workflow event ID recorded by OpsPilot.

The combined investigation requires the trace, Loki, Docker, and GitHub
selectors to reference sources/events in the same project and incident.
Grafana alert evidence is included automatically.

In OpsPilot's Swagger UI, use
`POST /projects/{project_id}/incidents/{incident_id}/investigate` with a body
like this, replacing every placeholder with the source IDs and event ID for
your project:

```json
{
  "traces": {
    "source_id": "<TEMPO-SOURCE-ID>",
    "service_name": "portfolio-api",
    "start": "<UTC-TIME-BEFORE-FAILURE>",
    "end": "<UTC-TIME-AFTER-FAILURE>",
    "limit": 5
  },
  "loki": {
    "source_id": "<LOKI-SOURCE-ID>",
    "start": "<UTC-TIME-BEFORE-FAILURE>",
    "end": "<UTC-TIME-AFTER-FAILURE>",
    "labels": {
      "service_name": "portfolio-api",
      "scenario": "portfolio-contact-database-outage"
    },
    "limit": 100
  },
  "docker": {
    "source_id": "<DOCKER-SOURCE-ID>",
    "container_id": "<API-CONTAINER-ID>",
    "log_tail_lines": 100
  },
  "github": {
    "repository_id": 1249219668,
    "event_id": "<FAILED-WORKFLOW-EVENT-UUID>"
  }
}
```

Use timezone-qualified ISO-8601 timestamps. The Loki labels must also appear
on the Grafana alert that created this incident. The failed workflow event is
available from
`GET /projects/{project_id}/github/repositories/1249219668/webhook-events`.

## Current OpsPilot limitation

The combined investigation endpoint does not have a direct Prometheus query
integration; it reports Prometheus as `not_configured`. This test exercises
Prometheus by using its metric in a Grafana alert, whose observed value and
labels are retained as Grafana evidence. It does not persist a separate raw
Prometheus query result. Do not treat the Grafana alert evidence as direct
Prometheus query support.

## Restore services

Restart PostgreSQL after the investigation:

```bash
docker compose --env-file test-harness/.env -f test-harness/docker-compose.yml start database
```

Stop the temporary tunnels, restore the original GitHub App webhook URL, and
stop the isolated stack when finished:

```bash
docker compose --env-file test-harness/.env -f test-harness/docker-compose.yml down
```
