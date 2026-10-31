# OpsPilot API

OpsPilot is a FastAPI backend using SQLAlchemy's async ORM, PostgreSQL, and
Redis. Start PostgreSQL and Redis, configure `.env`, and apply database
migrations before starting the API:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
docker run --name opspilot-redis -p 6379:6379 -d redis:7-alpine
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL, for example
`postgresql+asyncpg://...`. `REDIS_URL` defaults to `redis://localhost:6379`.
The API checks Redis and PostgreSQL on startup and closes Redis cleanly on
shutdown. Redis stores expiring OTP state and rate-limit counters; PostgreSQL
stores accounts, project memberships, and hashed refresh sessions. Check
`GET /health/ready` for PostgreSQL and Redis readiness.

Do not commit `.env` or use the example values as production credentials.
Generate each signing/pepper secret independently with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

For Loki connections, set `LOKI_ALLOWED_HOSTS` to a comma-separated exact
host allowlist (include `:port` when using a non-default port). Generate and
keep `LOKI_CREDENTIAL_ENCRYPTION_KEY` stable and backed up; it encrypts Loki
outbound credentials at rest:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Loki URLs must use HTTP or HTTPS and match this allowlist. Use HTTPS outside
trusted local networks. Loki sources support no authentication, bearer tokens,
or basic authentication. Authenticated Loki sources require the encryption key.

## Read-only Docker investigation

Docker integration inspects the Docker daemon available to the OpsPilot API
process. It does not expose a Docker proxy, manage hosted Docker services, or
receive telemetry. Configure the local daemon endpoint in the API process
environment; Docker endpoints are not stored in source records.

Set `DOCKER_HOST` only when the process's default endpoint is not correct. Use
the local Unix socket shown by your Docker Engine/Desktop setup, for example
`unix:///var/run/docker.sock` in a WSL distro with Docker Desktop WSL
integration enabled. On Windows-native Python, Docker Desktop commonly uses
`npipe:////./pipe/docker_engine`. OpsPilot rejects TCP endpoints, including
loopback TCP. Do not expose the Docker daemon or socket over a network.
`DOCKER_QUERY_TIMEOUT_SECONDS` bounds individual daemon requests; Docker log
output is capped by `DOCKER_LOG_MAX_BYTES`.

Docker daemon access is highly privileged. Despite OpsPilot's strictly
read-only API, a process that can access the daemon socket can often obtain
host-level control through Docker itself. Restrict access to the API process
and to trusted project members; do not make a local development daemon
available to untrusted users.

Apply database migrations and restart the API after configuring its local
daemon access. A project owner creates a source with
`POST /projects/{project_id}/sources`:

```json
{
  "name": "Local Docker",
  "source_type": "docker"
}
```

Use the returned source ID with these authenticated endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /projects/{project_id}/sources/{source_id}/docker/validate` | Check local daemon connectivity. |
| `GET /projects/{project_id}/sources/{source_id}/docker/containers` | List at most 100 containers, including stopped containers. |
| `POST /projects/{project_id}/docker/investigations` | Collect bounded evidence for one container; optionally include an `incident_id` to persist deduplicated incident evidence. |

For example, create a short-lived local test container using Docker CLI
(independent of OpsPilot), then use the returned container ID in an
investigation request:

```sh
docker run --rm -d --name opspilot-docker-test alpine:3.20 \
  sh -c 'echo "database connection refused"; sleep 30'
docker inspect --format '{{.Id}}' opspilot-docker-test
```

```json
{
  "source_id": "SOURCE_UUID",
  "container_id": "CONTAINER_ID",
  "log_tail_lines": 100
}
```

Send that body to
`POST /projects/{project_id}/docker/investigations` with an access token.
Include a project-scoped `incident_id` to save the evidence; without one, the
response is not persisted. A container ID must be a 12-64 character hexadecimal
ID. The investigation has bounded logs, a single stats snapshot, image
metadata, and recent Docker events. Memory is reported as a snapshot, not a
trend. Container environment-variable values, mount source paths, and labels
are omitted; common credentials in logs are redacted, but free-form logs may
still contain sensitive information and must be treated as untrusted input.
Docker CLI commands can change daemon state; OpsPilot itself only performs
read operations.

## OpenTelemetry traces

OpsPilot queries an existing Grafana Tempo trace backend; it does not receive
OTLP telemetry and does not require users to run an OpsPilot Docker stack.
Application OpenTelemetry SDKs create spans, and an OpenTelemetry Collector or
an SDK exporter sends them to a trace backend. Tempo stores those traces.
OpsPilot uses Tempo's query API (`/api/search` and `/api/traces/{traceID}`) to
retrieve bounded evidence. An OTLP ingest URL is not a trace-query endpoint.

Set `TRACE_ALLOWED_HOSTS` to a comma-separated exact-host allowlist for Tempo
(include `:port` for a non-default port). Keep `TRACE_CREDENTIAL_ENCRYPTION_KEY`
stable and backed up; it encrypts bearer/basic credentials at rest. Generate a
Fernet key with:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Trace URLs must use HTTP or HTTPS, contain no credentials/query/fragment, and
match the server allowlist. Prefer HTTPS. The API disables redirects and
environment-proxy inheritance, applies request timeouts, limits response
sizes, and rate-limits trace queries. For authenticated endpoints, configure
`trace_auth_type` as `bearer` or `basic`; credentials are never returned by the
source API. Project owners can test the connection using the
`/traces/validate` route.

Create a Tempo source under a project using `POST /projects/{project_id}/sources`:

```json
{
  "name": "Production Tempo",
  "source_type": "traces",
  "trace_backend": "tempo",
  "trace_url": "https://tempo.example.com",
  "trace_service_name": "checkout-api",
  "trace_resource_attributes": {
    "deployment.environment.name": "production"
  }
}
```

After an incident has relevant trace context, a project member can query
`POST /projects/{project_id}/incidents/{incident_id}/traces` with the source ID,
an ISO-8601 time range, and a trace ID or selectors. Selectors can include
`service_name`, `span_status` (`error`, `ok`, or `unset`),
`resource_attributes`, and `span_attributes`. Queries are limited to six
hours and at most ten traces; results are normalized into span IDs, parent
span IDs, service/operation names, timestamps, durations, statuses, and
attributes, then persisted as deduplicated `trace_spans` incident evidence.
Tempo search provides a result limit but no continuation cursor, so OpsPilot
does not attempt unsupported pagination. Unfiltered searches are rejected.
Trace retrieval is explicit/on-demand: alert intake does not automatically
fetch traces, and a trace-backend failure cannot roll back incident creation
or other evidence.

### Combined incident investigation

Use `POST /projects/{project_id}/incidents/{incident_id}/investigate` to
collect requested evidence together. The request names the source and
correlation criteria for each backend; OpsPilot does not guess which service,
container, or workflow is related to an incident. Each requested backend
reports its own result, and a failed integration does not prevent the other
requested integrations from running. The response includes all evidence
already attached to the incident, including Grafana/Alertmanager notifications.
GitHub workflow investigation evidence is persisted and deduplicated by event.

For example, provide a trace source and time range, Loki source and alert labels,
Docker source and container ID, and the repository/event IDs for a failed
GitHub workflow:

```json
{
  "traces": {
    "source_id": "TEMPO_SOURCE_UUID",
    "service_name": "checkout-api",
    "span_status": "error",
    "start": "2026-10-29T19:00:00Z",
    "end": "2026-10-29T19:10:00Z",
    "limit": 5
  },
  "loki": {
    "source_id": "LOKI_SOURCE_UUID",
    "start": "2026-10-29T19:00:00Z",
    "end": "2026-10-29T19:10:00Z",
    "labels": {
      "service_name": "checkout-api",
      "environment": "production"
    },
    "limit": 100
  },
  "docker": {
    "source_id": "DOCKER_SOURCE_UUID",
    "container_id": "CONTAINER_ID",
    "log_tail_lines": 100
  },
  "github": {
    "repository_id": 123456789,
    "event_id": "FAILED_WORKFLOW_EVENT_UUID"
  }
}
```

The time ranges and selectors should correspond to the incident. Trace and
Loki query ranges are bounded to six hours. Docker investigations require an
explicit container ID, and GitHub investigations require a failed or
unexpected workflow event. Every backend can return `success`, `empty`,
`partial`, or `unavailable`; the aggregate response also returns the incident's
persisted evidence.

Prometheus sources can store an endpoint and optional bearer/basic credentials.
Set `PROMETHEUS_ALLOWED_HOSTS` to a comma-separated exact-host allowlist and,
for authenticated sources, set and back up `PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY`.
Generate a Fernet key with the command shown in the Loki setup above.
Credentials are encrypted at rest and source responses expose only the auth
type and whether credentials are configured. This configuration is not yet a
direct query integration: Prometheus alert metadata is available only when
included in a Grafana or Alertmanager notification; OpsPilot does not yet
execute PromQL or fetch Prometheus time series.

Project owners can test the configured endpoint with
`POST /projects/{project_id}/sources/{source_id}/prometheus/validate`. The
check requests Prometheus's `/-/ready` endpoint without following redirects,
and applies `PROMETHEUS_QUERY_TIMEOUT_SECONDS`. The source reports the latest
connection status and check time; this check confirms reachability and
authentication, not metric-query permissions.

### Instrument a FastAPI application

Install the SDK, OTLP exporter, and FastAPI instrumentation in the application
that produces traces (not in OpsPilot):

```sh
pip install opentelemetry-sdk opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi
```

Configure an OTLP Collector or your existing OTLP receiver as the export
destination. For example, with a Collector listening for OTLP/gRPC on port
4317:

```sh
export OTEL_SERVICE_NAME=checkout-api
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.example.net:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
```

Initialize instrumentation before serving requests:

```python
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

app = FastAPI()
provider = TracerProvider(
    resource=Resource.create(
        {
            "service.name": "checkout-api",
            "deployment.environment.name": "production",
        }
    )
)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)
FastAPIInstrumentor.instrument_app(app)
```

Configure the Collector to receive OTLP and export traces to the Tempo
deployment; the Collector's OTLP receiver/exporter addresses are separate
from the Tempo query URL configured in OpsPilot. Verify trace ingestion in
Tempo's UI or API, then create and validate the Tempo source and query an
incident with the matching service name and time range. OpsPilot does not
automatically modify or instrument application repositories. Trace correlation
depends on the application exporting useful resource attributes such as
`service.name`, environment, and any trace IDs carried into incident context.

Configure SMTP (`SMTP_HOST`, `SMTP_FROM`, and either STARTTLS or implicit TLS)
before using registration, login, or password reset. The canonical username
setting is `SMTP_USER`; `SMTP_USERNAME` remains an accepted environment
variable alias. SMTP credentials must be provided together. The service does
not log OTPs or credentials, and does not fall back to logging verification
codes when email is unavailable. Configure comma-separated `FRONTEND_ORIGINS`
for credentialed browser CORS. For a cross-site frontend, configure
`REFRESH_COOKIE_SAMESITE=none` and keep `REFRESH_COOKIE_SECURE=true`. The
refresh cookie is Secure by default; only disable it for local HTTP testing.

For Brevo, authenticate the exact `SMTP_FROM` domain in Brevo and publish the
SPF and DKIM records shown in its domain settings. Merge Brevo's SPF mechanism
into the domain's existing SPF record; do not publish multiple SPF records.
Keep DMARC alignment in mind, especially when the domain's DMARC policy uses
`p=quarantine` or `p=reject`.

## Authentication API

All request and response bodies are JSON. Email addresses are normalized
before storage and comparisons.

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/register` | Begin public registration; accepts `email`, `display_name`, and `password`. Responds `202` generically and emails an OTP. Registration creates no project access. |
| `POST /auth/register/verify` | Accepts `email` and six-digit `code`; activates the account after email verification and returns tokens. |
| `POST /auth/login` | Accepts `email` and `password`; returns a generic response and sends an OTP for valid credentials. |
| `POST /auth/login/verify` | Accepts `email` and `code`; returns tokens after successful OTP verification. |
| `POST /auth/otp/resend` | Resends a challenge for `register`, `login`, or `reset`, subject to rate limits. `registration`, `password_reset`, and `forgot_password` are aliases. Resending replaces the previous code. |
| `POST /auth/password/reset` | Begin a non-enumerating password reset request. |
| `POST /auth/password/reset/verify` | Verifies an emailed OTP and returns a short-lived, single-use `reset_token`. |
| `POST /auth/password/reset/complete` | Accepts `reset_token` and `new_password`; updates the password and revokes refresh sessions. |
| `POST /auth/password/change` | Requires a bearer access token and `current_password` plus `new_password`; revokes refresh sessions. |
| `POST /auth/refresh` | Rotates the refresh session and returns a new access token. The refresh token is read only from the cookie. |
| `POST /auth/logout` | Revokes the current refresh session, if present, and clears its cookie. |
| `GET /auth/me` | Returns the verified profile and accessible projects with project roles; requires a bearer access token. |

Access tokens are short-lived JWTs returned in the JSON body and sent as a
bearer authorization header. Refresh tokens use a separate signing secret, are
stored only as hashes in PostgreSQL, and are set in an `HttpOnly` cookie scoped
to `/auth`. The API never returns refresh tokens in JSON. Each refresh rotates
the token; reuse of a revoked token revokes that token family. Logout revokes
the current refresh session. Already issued access tokens expire naturally
within 15 minutes; logout and password changes do not immediately revoke access
JWTs.

OTP codes expire after `OTP_EXPIRE_MINUTES` (five minutes by default), are
single-use, and allow at most `OTP_MAX_ATTEMPTS` verification attempts. Only an
HMAC hash is held in Redis; the purpose is bound to the challenge and
verification is atomic. Resends are limited by `OTP_MAX_RESENDS` per challenge
and separate per-email/per-IP Redis counters shared across API workers. Defaults
are five minutes, three attempts, and three resends. `OTP_HASH_SECRET_KEY` must
contain at least 32 bytes.

## Project API

Projects are the active ownership and access boundary. Public account
registration creates a user only; it does not create a project or grant access.
Organization and invitation routes, models, and storage have been removed.

| Endpoint | Purpose |
| --- | --- |
| `POST /projects` | Create a project for the authenticated user; the creator becomes its `owner`. |
| `GET /projects` | List only projects where the authenticated user has a project membership. |
| `GET /projects/{project_id}` | Retrieve a project only if the authenticated user is a member. |
| `PATCH /projects/{project_id}` | Update project name or description; only project owners may update. |
| `DELETE /projects/{project_id}` | Delete a project and its memberships/environments; only project owners may delete. |

Project roles are `owner` and `member`. Members can view projects but cannot
update or delete them. Project queries are scoped by the authenticated user's
project membership; a project UUID alone does not grant access. Environments
are project-owned database resources and are deleted with their project. The
environment model exists, but environment-management endpoints and invitation
endpoints are not implemented.

## Event sources and incidents

A project owner creates a source and configures the sending system with its
webhook URL and bearer credential. The credential is shown only at creation or
rotation; store it in the sending system as a secret. OpsPilot receives events
but does not monitor infrastructure itself.

Generic webhook sources store each event and create one open incident. Repeated
deliveries with the same event ID return the existing event and incident.
Alertmanager sources accept Alertmanager's native batch format. Each alert is
identified by its fingerprint within its source: repeated firing notifications
update the existing alert, and a resolved notification resolves the associated
incident only when no other linked Alertmanager alert remains firing. Exact
retries do not create duplicate incidents or duplicate evidence. Updated
provider payloads are retained as incident evidence.

Loki is a pull-based evidence source, not an alert webhook. Create a source
with `source_type: "loki"` and its base URL, optional tenant ID, and supported
authentication settings. For an incident created from Grafana or Alertmanager,
call `POST /projects/{project_id}/incidents/{incident_id}/loki-logs` with the
Loki source ID, a time range of at most six hours, and one or more selector
labels whose values exactly match labels already recorded on that incident.
OpsPilot builds a safe LogQL stream selector, queries Loki's
`/loki/api/v1/query_range` API, and stores bounded results as incident evidence.
Repeated retrievals for the same source, incident, selector, range, and limit
update the corresponding evidence instead of adding a duplicate record.
Selectors are unavailable for manual incidents or incidents without Grafana or
Alertmanager labels.

Example Loki source creation (with no Loki authentication):

```json
{
  "name": "Production Loki",
  "source_type": "loki",
  "loki_url": "https://loki.example.com",
  "loki_tenant_id": "tenant-1",
  "loki_auth_type": "none"
}
```

Authenticated source creation uses `loki_auth_type: "bearer"` with
`loki_bearer_token`, or `loki_auth_type: "basic"` with `loki_username` and
`loki_password`. Secrets are encrypted using
`LOKI_CREDENTIAL_ENCRYPTION_KEY` and are never returned by source APIs. Loki
hostnames are restricted by `LOKI_ALLOWED_HOSTS`; an explicit non-default port
must also appear in that allowlist.

Grafana sources accept Grafana Alerting's default webhook notification format
at `/webhooks/sources/{source_id}/grafana`. Grafana alert fingerprints are
deduplicated within their source and use the same alert lifecycle and incident
pipeline as Alertmanager. Original webhook data, including Grafana dashboard,
panel, silence, image, and value metadata, is retained in evidence. Configure
the Grafana webhook contact point with the source credential as its HTTP
Authorization bearer token and enable resolved notifications. See the
[Grafana webhook notifier documentation](https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/).

When a Grafana or Alertmanager firing notification creates or updates an
incident, OpsPilot automatically checks each enabled Loki source in that
project. It discovers which alert label name/value pairs exist in Loki, then
queries matching logs from five minutes before the alert start through receipt
time (capped at six hours) and stores them as incident evidence. The webhook
response reports successful, empty, skipped, rate-limited, or failed retrieval
status for each Loki source. Loki failures do not undo the already-persisted
alert; a later firing notification retries if no Loki evidence was stored.
Manual incidents do not trigger automatic Loki retrieval because they do not
provide provider alert labels or a firing timestamp.

To create an Alertmanager source, an owner uses
`POST /projects/{project_id}/sources` with:

```json
{
  "name": "Production Alertmanager",
  "source_type": "alertmanager"
}
```

Configure Alertmanager to POST to
`/webhooks/sources/{source_id}/alertmanager`, with the returned source
credential as a Bearer token. The endpoint accepts native Alertmanager
notification batches. Each new firing fingerprint creates its own incident;
this milestone does not correlate separate alerts that may share a root cause.
When an alert resolves, its incident is resolved only after its other linked
alerts are no longer firing. A later firing notification for that fingerprint
reopens the same incident.

| Endpoint | Purpose |
| --- | --- |
| `POST /projects/{project_id}/sources` | Create a generic webhook, Alertmanager, Grafana, Loki, Prometheus, Tempo trace, or Docker source; owner only. |
| `GET /projects/{project_id}/sources` | List source metadata; project members only. |
| `GET /projects/{project_id}/sources/{source_id}` | Retrieve one source within the project; project members only. |
| `PATCH /projects/{project_id}/sources/{source_id}` | Partially update source name, environment, enabled state, or its provider configuration; owner only. Omitted fields are preserved. Set a provider's `*_auth_type` to `none` to clear its stored credentials. |
| `DELETE /projects/{project_id}/sources/{source_id}` | Delete an unused source; owner only. Sources with event, alert, or evidence history cannot be deleted and should be disabled instead. |
| `POST /projects/{project_id}/sources/{source_id}/rotate-credential` | Rotate the source secret; owner only. |
| `POST /projects/{project_id}/sources/{source_id}/disable` | Disable webhook intake; owner only. |
| `PATCH /projects/{project_id}/sources/{source_id}/loki` | Update Loki URL, tenant, authentication, or enabled state; owner only. Responses never include Loki credentials. |
| `PATCH /projects/{project_id}/sources/{source_id}/prometheus` | Update Prometheus URL, authentication, or enabled state; owner only. Responses never include Prometheus credentials. |
| `PATCH /projects/{project_id}/sources/{source_id}/traces` | Configure a Tempo query endpoint, tenant, authentication, service, and resource attributes; owner only. Responses never include credentials. |
| `POST /projects/{project_id}/sources/{source_id}/traces/validate` | Check the Tempo query API connection and record its status; owner only. |
| `POST /webhooks/sources/{source_id}` | Receive a generic event using the source's bearer credential; creates an incident. |
| `POST /webhooks/sources/{source_id}/alertmanager` | Receive an Alertmanager batch using the source's bearer credential; creates or updates alerts and incidents. |
| `POST /webhooks/sources/{source_id}/grafana` | Receive a Grafana Alerting batch using the source's bearer credential; creates or updates alerts and incidents. |
| `POST /projects/{project_id}/incidents` | Report an incident manually; any authenticated project member. |
| `GET /projects/{project_id}/incidents` | List incidents in a project. |
| `GET /projects/{project_id}/incidents/{incident_id}` | Retrieve an incident within that project. |
| `PATCH /projects/{project_id}/incidents/{incident_id}/status` | Change incident status through allowed transitions. |
| `GET /projects/{project_id}/incidents/{incident_id}/evidence` | Retrieve the saved original and normalized report/event data. |
| `POST /projects/{project_id}/incidents/{incident_id}/loki-logs` | Query the selected Loki source for bounded, incident-label-matched logs and persist them as evidence; project members only. |
| `POST /projects/{project_id}/incidents/{incident_id}/traces` | Query the selected Tempo source for bounded traces using a trace ID or selectors and persist evidence; project members only. |
| `GET /projects/{project_id}/events` | List received webhook events. |
| `GET /projects/{project_id}/events/{event_id}` | Retrieve one event and its original payload. |

Incident statuses start at `open`; supported transitions are
`open` to `acknowledged` or `resolved`, `acknowledged` to `open` or `resolved`,
and `resolved` to `open`. An incident with a linked firing Alertmanager alert
cannot be manually resolved. Source events and incident evidence are stored
separately. Access to project incidents and events requires project membership;
webhooks require their source credential. There is not yet an AI investigation, cross-alert correlation, or remediation
workflow.

## GitHub App integration

GitHub repositories are authorized through a GitHub App installation, then
explicitly connected to an OpsPilot project. Set the GitHub App's single
webhook URL to a publicly reachable HTTPS URL ending in `/webhooks/github`.
Subscribe only to **Workflow run** in the GitHub App's **Permissions & events**
settings. OpsPilot stores completed runs with a conclusion other than
`success`, `neutral`, `skipped`, or `cancelled`; pushes, pull-request activity,
successful runs, and in-progress runs are acknowledged but not stored. The
App needs repository read access to **Actions** for run details and logs, and
**Contents** for commit and code-change details. The workflow-run payload
includes the run, commit, branch, and log API references needed to investigate
failures.

GitHub sends subscribed events to this central endpoint. OpsPilot verifies the
signature and stores relevant deliveries for every project that has connected
that repository. It does not create repository-level GitHub webhooks or send
GitHub comments, statuses, or notifications. A local development server needs
a running public HTTPS tunnel; temporary quick-tunnel URLs stop working when the
tunnel exits and are not suitable for a permanent webhook URL.

`GET /projects/{project_id}/github/repositories/{repository_id}/webhook-events`
lists events already received and stored; an empty list means no matching
delivery has been stored yet. This endpoint does not query GitHub's delivery
history. Use
`GET /projects/{project_id}/github/repositories/{repository_id}/webhook-events/{event_id}/investigation`
to fetch a stored failed run's current GitHub run details, jobs, commit and
changed-file patches and source contents (up to ten text files of at most 1 MiB
each; binary, removed, and oversized files are identified as unavailable), the
ten most recent commits up to the failing commit, and workflow logs. This
investigation context is fetched on demand rather than stored or fetched for
every webhook; log output and code-file retrieval are bounded. It does not
create an incident automatically.

## Current scope

The backend currently provides authentication, project-level ownership and
membership, generic webhook event intake, Alertmanager and Grafana alert
lifecycle intake, Loki log evidence retrieval, manual and webhook-created
incidents, and persisted evidence. It does not yet
run an AI investigation or remediation workflow. The
migration removing the legacy organization and invitation schema refuses to
run while records in those legacy tables remain; it preserves users, projects,
project memberships, and environments. This migration is irreversible.

## Tests

Install test dependencies with `pip install -r requirements-dev.txt`, then run:

```sh
pytest
```
