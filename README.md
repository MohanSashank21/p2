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
| `POST /projects/{project_id}/sources` | Create a generic webhook, Alertmanager, Grafana, or configured Loki source; owner only. |
| `GET /projects/{project_id}/sources` | List source metadata; project members only. |
| `POST /projects/{project_id}/sources/{source_id}/rotate-credential` | Rotate the source secret; owner only. |
| `POST /projects/{project_id}/sources/{source_id}/disable` | Disable webhook intake; owner only. |
| `PATCH /projects/{project_id}/sources/{source_id}/loki` | Update Loki URL, tenant, authentication, or enabled state; owner only. Responses never include Loki credentials. |
| `POST /webhooks/sources/{source_id}` | Receive a generic event using the source's bearer credential; creates an incident. |
| `POST /webhooks/sources/{source_id}/alertmanager` | Receive an Alertmanager batch using the source's bearer credential; creates or updates alerts and incidents. |
| `POST /webhooks/sources/{source_id}/grafana` | Receive a Grafana Alerting batch using the source's bearer credential; creates or updates alerts and incidents. |
| `POST /projects/{project_id}/incidents` | Report an incident manually; any authenticated project member. |
| `GET /projects/{project_id}/incidents` | List incidents in a project. |
| `GET /projects/{project_id}/incidents/{incident_id}` | Retrieve an incident within that project. |
| `PATCH /projects/{project_id}/incidents/{incident_id}/status` | Change incident status through allowed transitions. |
| `GET /projects/{project_id}/incidents/{incident_id}/evidence` | Retrieve the saved original and normalized report/event data. |
| `POST /projects/{project_id}/incidents/{incident_id}/loki-logs` | Query the selected Loki source for bounded, incident-label-matched logs and persist them as evidence; project members only. |
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
