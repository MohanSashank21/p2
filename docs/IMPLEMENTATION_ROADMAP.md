# OpsPilot AI: system verification and implementation roadmap

**Status:** M4 live acceptance is complete. Current local verification
supports proceeding to M5; M9 remains partial because these checks do not
certify every production environment or every provider failure mode.

**Repository baseline:** `main` at `5ccb57e` (`add the git and open telemtry
services`) when this review began.

## Purpose and scope

This document records what the current OpsPilot backend does, what was
verified, what is missing for evidence-backed AI incident investigation, and
the proposed implementation order. It is a plan, not approval to implement all
milestones. Each implementation increment must be reviewed and approved before
the next begins. The user makes all commits and pushes.

The repository root is a FastAPI backend. A local `akmatori/` reference
directory is ignored by this repository's `.gitignore`; it is not part of the
tracked OpsPilot application or its runtime. Akmatori and other products are
references for architectural patterns, not services OpsPilot currently calls.

## Verification method and classification

The review inspected the application routes, services, schemas, SQLAlchemy
models, migrations, tests, configuration, and README. It did not inspect the
private `.env` file or attempt to connect to its configured services.

Status definitions:

- **Verified working:** relevant tests or safe execution confirm the stated
  behavior. The verification boundary (SQLite, mocks, or live dependency) is
  stated; tests with mocks do not verify a live third-party service.
- **Implemented, not fully verified:** implementation exists, but an important
  runtime dependency or database-specific behavior was not verified.
- **Partially implemented:** there is useful functionality, but material
  requirements remain absent.
- **Not implemented:** no meaningful implementation was found.
- **Blocked:** verification needs a service, deployment, or configuration that
  was unavailable or intentionally not contacted.

## Baseline verification results

- Working tree was clean on `main` before this document was added.
- `PYTHONPATH=/mnt/c/Users/hp/OneDrive/Desktop/p2 ./myenv/bin/pytest -q -rs`:
  **71 passed, 1 skipped**.
- After the first approved tool increment, the full suite reports
  **77 passed, 1 skipped**. The six added tests cover registry validation,
  scoped invocation, and the Loki adapter contract.
- After the Tempo adapter increment, focused tool/source tests report
  **37 passed, 1 skipped**.
- Full suite after the Tempo adapter: **80 passed, 1 skipped**. The first
  full run had one unrelated auth test failure; that test passed alone and the
  repeated full run passed.
- Docker adapter focused tests: **22 passed**; full suite after Docker:
  **83 passed, 1 skipped**.
- GitHub adapter focused tests: **20 passed**; full suite after GitHub:
  **86 passed, 1 skipped**.
- Incident-evidence adapter, incident API, and source tests: **36 passed,
  1 skipped**; full suite after the adapter: **90 passed, 1 skipped**.
- The skipped test is
  `tests/test_sources.py::test_alertmanager_concurrent_repeated_firing_notifications_are_idempotent`;
  it requires PostgreSQL row-lock behavior. The suite's test fixtures use
  temporary SQLite databases, fake Redis, and mocked external clients for
  provider/daemon interactions.
- `./myenv/bin/alembic heads` reported one head: `8d4a2c6e1f90`.
  `alembic history --verbose` displayed a single migration chain. This checks
  the migration graph, not the schema version or migration state of any live
  database.
- Plain `pytest` and `alembic` were not on the shell `PATH`; the existing
  project virtual-environment entry points were used. No dependencies were
  installed.
- No live PostgreSQL, Redis, GitHub, Grafana/Alertmanager, Loki, Tempo, or
  Docker checks were performed against this checkout. Prior user-run Portfolio
  harness testing is not treated as OpsPilot runtime verification.

## Existing architecture and data flows

### Authentication and project access

```text
Client
  -> FastAPI auth route
  -> Redis OTP challenge / rate-limit scripts
  -> SMTP delivery
  -> PostgreSQL user and hashed refresh-session records

Client access token
  -> get_current_user validates JWT and verified user
  -> route/service checks project membership and (where required) owner role
  -> project-scoped data query or mutation
```

Access tokens are short-lived JWTs. Refresh tokens are stored as hashes in
PostgreSQL and rotated; password changes/reset revoke refresh sessions. OTP
challenges and rate limits use Redis Lua scripts. Refresh cookies are
HTTP-only, and cookie-origin checks are applied to refresh/logout routes.

There is **no active Organization model or organization-membership flow** in
the current application. Access is project-scoped: a `ProjectMembership` has
role `owner` or `member`. Project creation establishes its owner membership.
The migration `b9d73f0a2c61` removes the legacy organization and invitation
schema and is explicitly irreversible; it refuses to run when legacy records
remain. The route test confirms old organization endpoints return 404.

### Alert ingestion and incidents

```text
Grafana / Alertmanager / generic source
  -> source bearer credential verification (stored credential hash)
  -> Redis source-event rate limit
  -> payload size and Pydantic validation
  -> SQL transaction:
       SourceEvent + Incident + IncidentEvidence
       or ProviderAlert lifecycle update + notification evidence
  -> firing Grafana/Alertmanager alert may trigger bounded Loki retrieval
```

Generic webhook events are deduplicated by source and external event ID.
Grafana and Alertmanager alerts are tracked by source and fingerprint;
repeated firing/resolved notifications update the same alert/incident
lifecycle. Alert evidence preserves provider payload and normalized labels.
When an alert is firing, matching Loki sources may be queried automatically.
Loki query failures are reported in the retrieval result rather than being
silently treated as evidence.

Manual incident creation and status updates use project-scoped access.
Resolving an incident is blocked while linked provider alerts remain firing.
Incident evidence is persisted in `incident_evidence` as original and
normalized JSON payloads; there is no separate investigation-run or AI-finding
record today.

### Explicit incident investigation

```text
POST /projects/{project_id}/incidents/{incident_id}/investigate
  -> authenticate user and verify project/incident access
  -> accept caller-selected Loki, Tempo, Docker, and/or GitHub criteria
  -> execute requested integrations in the API request
  -> persist bounded evidence (where supported)
  -> return per-integration status plus all incident evidence
```

The caller supplies the source IDs and selectors/container/workflow criteria;
OpsPilot does not currently plan queries automatically. The response exposes
`success`, `empty`, `partial`, `unavailable`, `included`, or
`not_configured`. Integrations are processed sequentially in this service.
Provider alert evidence is included in the response; Prometheus is always
reported as `not_configured` for direct querying.

The approved Stage 1 increments add an internal static read-only tool registry
and Loki/Tempo/Docker/GitHub/incident-evidence adapters. Integration adapters
wrap the existing combined-investigation service and return typed results
with persisted evidence references, completeness, and truncation metadata.
The incident-evidence adapter reuses the project-authorized evidence service
with bounded paging and optional evidence-type filters. These additions add
no public endpoint and preserve existing route behavior.

Loki and Tempo clients use source configuration, server-side host allowlists,
timeouts, no redirects, response bounds, and rate limits. Authenticated source
credentials are encrypted at rest using configured Fernet keys; secrets are
not returned by source APIs. Tempo queries normalize spans and enforce
bounded searches. Docker investigation is read-only and restricts daemon
access to local Unix sockets or Windows named pipes; evidence bounds/redacts
logs and omits sensitive container values. GitHub investigation fetches a
bounded set of run/job/commit/file/log context.

### GitHub App and CI workflow evidence

```text
GitHub App setup (owner-only)
  -> short-lived Redis state
  -> GitHub installation / selected project repository

GitHub webhook
  -> HMAC signature verification
  -> completed workflow-run failure filtering
  -> event stored for projects connected to that repository
  -> later, explicit authenticated investigation request
  -> short-lived installation token -> workflow/jobs/commit/files/logs
  -> optional evidence attachment to an incident
```

The app requests read access for Actions, Contents, and Metadata. The webhook
stores unexpected/failed completed workflow runs, not successful runs or
in-progress events. It does not create incidents automatically. Context is
fetched on demand. An authenticated live combined-investigation request
successfully fetched and persisted context for an existing real failed
Portfolio workflow run. The matching incident did not contain the event's
workflow-run ID or commit SHA, so no cross-source GitHub correlation was
reported. Automated GitHub provider tests use mocks; see the M4 decision record
for the live run identifiers and evidence.

## Capability verification matrix

| Subsystem | Status | Evidence and boundary |
|---|---|---|
| Authentication (registration/login OTP, password reset/change, refresh/logout) | **Partially live-verified** | Auth API tests pass with temporary SQLite/fake email delivery. The actual Redis OTP and rate-limit Lua scripts passed isolated live checks. Real SMTP delivery and the complete registration/login flow were not independently exercised in this pass; the user confirmed those workflows work. |
| User management | **Verified working** | User creation and auth flows are covered by passing tests. |
| Organization management and membership | **Not implemented (intentionally removed)** | Current model/API has project membership only; legacy tables were removed by migration; old-route test expects 404. |
| Project authorization and owner/member permissions | **Verified working** | Project and source tests cover membership/owner boundaries and project isolation using SQLite. |
| Database models and relationships | **Live schema-checked; concurrency partial** | Configured local PostgreSQL readiness succeeded and `alembic check` found no metadata drift. The PostgreSQL row-lock concurrency test remains skipped in the normal SQLite suite. |
| Async SQLAlchemy session management | **Live readiness verified** | The running API queried its configured PostgreSQL successfully; request-path tests also pass with SQLite. This does not certify every production deployment/pool condition. |
| Alembic migrations | **Current database verified at head** | `alembic current` reported `91d6c3a8f4b2` and read-only `alembic check` reported no pending operations. No migration was applied during verification; blank-database and upgrade-from-every-historical-revision paths were not rerun. |
| Redis | **Live script paths verified** | API readiness passed. The real rate-limit Lua script rejected over-limit calls, and the real OTP Lua challenge accepted a generated code and locked out after the configured invalid attempts using temporary unique keys. No real email delivery was triggered; GitHub setup state was not re-exercised in this pass. |
| Incident creation and lifecycle | **Verified working** | Tests cover manual/webhook creation, evidence, project isolation, valid transitions, and active-alert resolution guard in SQLite. |
| Combined investigation orchestration | **Partially implemented** | A tested synchronous integration orchestrator exists for Loki, Tempo, Docker, and GitHub; it is caller-directed and has no AI planning or durable run record. |
| Source management and credential handling | **Verified working (isolated tests)** | Project-scoped source creation, one-time source credential, rotation/disable, encrypted Loki/Tempo configuration, and owner checks have passing tests. |
| Grafana and Alertmanager webhooks | **Live-verified (acceptance scenario)** | Payload, lifecycle, deduplication and Loki follow-up tests pass; a live Grafana alert was delivered to OpsPilot with HTTP 200 and updated the test incident. |
| Direct Prometheus querying | **Implemented, live-verified** | Bounded read-only instant and range query tools use the configured source and project authorization. The combined investigation API persists query results as incident evidence. Docker Prometheus queries for `up`, an empty metric, invalid PromQL, and persisted `up` evidence were exercised. |
| Loki query/retrieval | **Live-verified (acceptance scenario)** | Query validation, bounds, evidence persistence/deduplication, empty response and timeout are covered by tests; a live authenticated investigation persisted a log entry containing the controlled trace ID. |
| Tempo trace retrieval | **Live-verified (acceptance scenario)** | Configuration, validation, normalization, evidence persistence/deduplication, auth and timeout cases are covered by tests; a live authenticated investigation persisted six spans for the controlled trace ID. |
| Docker investigation | **Live-verified (read-only, no persistence)** | Authenticated OpsPilot validation, container listing, and investigation of the existing test API container all succeeded. Missing credentials returned 401. No incident ID was supplied, so evidence was not persisted; failure paths and persistence remain covered by automated mocked-daemon tests. |
| GitHub App and workflow investigation | **Live-verified (on-demand retrieval only)** | A real stored failed Portfolio run was retrieved through the authenticated incident investigation API and persisted as evidence; no exact correlation to other incident evidence was present. Automated provider tests use mocks. |
| CI/CD integration | **Partially implemented** | GitHub Actions workflow-run evidence is available on demand; no auto-created incident, CI deployment metadata integration, or checked-in OpsPilot CI workflow was found. |
| LLM/AI investigation and recommendations | **Not implemented** | No LLM dependency, provider configuration, prompt/tool orchestration, structured finding, or model-output persistence was found. |
| Background execution | **Not implemented** | Integration queries and webhook follow-up execute in API requests; no task queue, worker, scheduler, or durable investigation job was found. |
| API contracts | **Verified working (test boundary)** | FastAPI routes and Pydantic request/response models are present; OpenAPI/webhook and endpoint tests pass. No separate compatibility/versioning policy was found. |
| Logging, metrics, tracing, health | **Partially implemented** | Python logging and DB/Redis health/readiness endpoints exist. No OpsPilot Prometheus metrics or OpenTelemetry instrumentation/dependency was found. |
| Automated tests | **Verified working (isolated suite plus opt-in live test)** | Current full backend suite: 143 passed, 2 skipped. The opt-in live Prometheus integration test was run separately and passed. The PostgreSQL-dependent row-lock test remains skipped in the full SQLite test suite; external-provider tests generally use mocks. |
| Docker/local development configuration | **Partially implemented** | README documents API setup and a Redis `docker run`; no tracked OpsPilot Compose file or app Dockerfile was found. PostgreSQL must be available/configured separately. |

## Reusable components and design constraints

Reuse and extend these existing boundaries rather than duplicating them:

- `get_current_user`, `get_accessible_project`, and
  `get_project_incident` for identity and project isolation.
- `IncidentSource` and `source_service` for project-scoped source ownership
  and lifecycle; Loki/Tempo already provide URL validation, allowlisting,
  encrypted credentials, and source APIs.
- `IncidentEvidence` and the existing integration services for evidence
  persistence and per-source query metadata.
- `IntegrationInvestigationResult` and the combined investigation response
  for explicit unavailable/empty/partial states.
- `github_service` / `github_project_service` for GitHub App and workflow
  access.
- The existing Redis service for bounded rate limits; do not use Redis as a
  substitute for durable investigation history.

Any future investigation engine should depend on small typed evidence-query
interfaces and consume normalized evidence. It should not directly implement
parallel versions of source management, authentication, Loki, Tempo, Docker,
or GitHub clients. Logs, provider payloads, and repository contents must be
treated as untrusted input if ever sent to a model.

## Target architecture

```text
Alert/webhook or authorized user
  -> existing FastAPI authentication and project authorization
  -> incident context builder
       incident, provider alert, labels, environment, time window
  -> investigation run (durable state and bounded execution)
  -> read-only evidence adapters
       Prometheus | Loki | Tempo | Docker | GitHub
  -> normalized evidence with source/query/time/provenance
  -> deterministic correlation and timeline
  -> optional LLM synthesis over selected evidence only
  -> structured observations, hypotheses, confidence, and recommendations
  -> user review; remediation is not executed by the investigator
```

The system must distinguish observed facts from hypotheses, cite persisted
evidence for each conclusion, represent missing/failed sources explicitly, and
avoid claiming root cause when evidence is insufficient. Remediation remains
outside the investigator's authority until separately designed, permissioned,
audited, and approved by a human.

## Implementation roadmap

Milestones are ordered by dependency. Each is a review gate; completing or
approving this roadmap does not authorize implementation of subsequent items.
The exact file list and tests will be confirmed immediately before each
increment.

### M0 — Repository verification and roadmap

**Status:** Complete (this document and the inspection above).

**Acceptance:** Relevant subsystems, verification limits, baseline tests,
architecture, risks, and dependency-ordered milestones are documented without
changing application code.

### Stage 1.1 — Static tool registry and Loki vertical slice

**Status:** Complete; further adapters require separate approval.

**Objective:** Establish a typed read-only tool contract, deterministic
registry/discovery, strict runtime argument validation, project/incident
authorization at invocation, and one adapter that reuses the existing Loki
investigation service.

**Implemented:** `app/tools/contracts.py`, `app/tools/registry.py`,
`app/tools/loki.py`, package exports, and focused registry/Loki tests. Existing
routes, source services, provider clients, and API response schemas were not
modified. Non-read-only tools and duplicate names are rejected.

**Acceptance:** Registry discovery exposes the Pydantic input schema; invalid
arguments return a structured error; project/incident authorization precedes
dispatch; the Loki adapter returns persisted evidence and marks results at the
requested limit as potentially truncated; known integration failures are
explicit. Focused source regressions and the full suite pass (77 passed, 1
skipped).

### Stage 1.2 — Tempo tool adapter

**Status:** Complete; further adapters require separate approval.

**Objective:** Expose the existing bounded Tempo query and evidence-persistence
path through the same typed, read-only tool contract.

**Implemented:** `app/tools/tempo.py` adds `tempo.query_incident_traces`,
registered alongside Loki. Both adapters share evidence serialization through
`app/tools/evidence.py`. The Tempo adapter delegates to the existing
investigation service, preserving query validation, project/source
authorization, provider bounds, rate limiting, and evidence persistence. A
search reaching its configured trace limit is marked potentially truncated;
an exact trace-ID lookup is not marked truncated solely because its expected
single result meets a limit of one.

**Acceptance:** Integration request criteria match the supplied typed
arguments; persisted trace/span counts and evidence provenance are returned;
unavailable results are explicit; limit and exact-ID completeness behavior
have focused tests; Loki/source regression tests pass. Focused result:
37 passed, 1 skipped. Full suite: 80 passed, 1 skipped after rerunning one
unrelated transient auth-test failure.

### Stage 1.3 — Docker tool adapter

**Status:** Complete; further adapters require separate approval.

**Objective:** Expose the existing local-daemon, bounded read-only container
investigation and evidence persistence through the same typed tool contract.

**Implemented:** `app/tools/docker.py` adds
`docker.investigate_incident_container`, registered alongside Loki and Tempo.
It delegates project/source authorization and collection to the existing
investigation service, includes persisted findings/provenance, surfaces
partial collector failures, and retains bounded-log truncation metadata. It
does not add daemon endpoints or allow write operations.

**Acceptance:** Existing request validation restricts container IDs and
requested log lines; invocations go through project/incident and source scope;
success, partial, truncation, and unavailable outcomes are covered by focused
tests. Focused Docker/tool result: 22 passed. Full suite: 83 passed,
1 skipped. The test suite uses mocked Docker interactions, not a live daemon.

### Stage 1.4 — GitHub workflow tool adapter

**Status:** Complete; further adapters require separate approval.

**Objective:** Expose the existing project-scoped failed-workflow context
retrieval and incident evidence persistence through the common read-only tool
contract.

**Implemented:** `app/tools/github.py` adds
`github.investigate_failed_workflow`, registered with the existing tools. It
delegates repository/event authorization and GitHub App access to the existing
investigation service, returns stored workflow context with an evidence
reference, and identifies repository content and logs as untrusted. Missing
logs, unavailable changed-file content, and provider truncation are surfaced
as partial completeness rather than success.

**Acceptance:** Existing service restrictions to a connected project
repository and failed/unexpected completed workflow run remain in force;
unavailable and incomplete outcomes are explicit; no GitHub write action is
exposed. Focused GitHub/tool tests: 20 passed. Full suite: 86 passed,
1 skipped. Provider calls are mocked; a live GitHub App was not exercised.

### Stage 1.5 — Incident evidence retrieval tool

**Status:** Complete; further milestones require separate approval.

**Objective:** Expose persisted incident evidence to the investigation engine
without duplicating incident authorization or evidence persistence.

**Implemented:** `app/tools/incident_evidence.py` adds
`incident.read_evidence` with bounded pages, offset, and optional evidence-type
filters. It reuses `list_incident_evidence`, which applies project/incident
authorization and now accepts optional query bounds; existing API callers
retain their original unbounded response behavior. Tool output includes
evidence provenance and flags payloads as untrusted. A page with additional
records reports partial completeness and the next offset.

**Acceptance:** Tests cover pagination, evidence-type filters, empty results,
invalid arguments, authorization path, and generated SQL bounds. Existing
incident routes/source tests pass. Focused evidence/incident/source result:
36 passed, 1 skipped. Full suite: 90 passed, 1 skipped.

### Stage 1.6 — Tool trust and persistence metadata

**Status:** Implemented; awaiting review.

**Objective:** Make tool results consistently identify untrusted content, and
make discovery distinguish provider-side read-only behavior from persisted
incident-evidence side effects.

**Implemented:** `ToolResult.content_is_untrusted` provides a top-level trust
marker. Provider investigation tools set `ToolDefinition.persists_evidence`,
which is exposed in `ToolDescriptor`; the incident evidence reader correctly
does not claim to persist records. `read_only` is documented as excluding
provider mutations while allowing separately declared evidence persistence.
Existing result data and public API contracts remain unchanged.

**Verification:** Focused registry and adapter tests: 20 passed. Full suite:
95 passed, 1 skipped; the skipped PostgreSQL row-lock concurrency test still
requires PostgreSQL. No live integrations were contacted.

### M1 — Direct Prometheus source configuration and validation

**Status:** In progress; M1.1, M1.2, and M1.3 implemented and awaiting review.

**Objective:** Reuse project source management to configure a Prometheus
endpoint safely, enforce server-side host allowlisting and bounded
authentication configuration, and provide an owner-only connection check.

**Small increments:** (1) source schema/model/migration and project-scoped
service validation; (2) credential protection and source API contract; (3)
owner-only connection validation. Do not query arbitrary PromQL or alter
existing Grafana/Alertmanager webhook contracts in this milestone.

#### M1.1 — Prometheus source schema and project-scoped configuration

**Status:** Implemented; awaiting review.

**Implemented:** Added the `prometheus` source type and `prometheus_url`
configuration to source creation/list responses, a project-owner-only
configuration update route, the nullable database column migration, and
`PROMETHEUS_ALLOWED_HOSTS` validation. Prometheus source retrieval verifies
project membership, project/source/type matching, enabled state, and
configuration before returning the source. URL credentials, query strings,
fragments, dot segments, unapproved hosts, and missing host allowlists are
rejected. No Prometheus authentication credentials, connection check, or
PromQL query client were added in this increment.

**Verification:** Prometheus-focused source tests: 2 passed. Source suite:
30 passed, 1 skipped. Incident API regression tests: 4 passed. Full suite:
92 passed, 1 skipped; the skipped PostgreSQL row-lock concurrency test still
requires PostgreSQL. `alembic heads` reports the new migration as the single
head, and the migration compiles when targeting only the new revision. Full
offline compilation of the entire historical chain remains blocked by the
pre-existing `e2a4c8910b7f` data migration, which requires an online database
connection. No live Prometheus or database migration was run.

**Acceptance:** Cross-project access is rejected; secrets never appear in
responses/logs; unsafe destinations/redirects are rejected; configuration
round-trips safely; migration upgrades an existing schema without data loss;
focused source/project regression tests pass.

#### M1.2 — Encrypted Prometheus credentials and source response contract

**Status:** Implemented; awaiting review.

**Implemented:** Added optional bearer/basic Prometheus authentication to
source creation and owner-only configuration updates. Credentials use a
dedicated `PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY` Fernet key and are stored only
as ciphertext. Source responses expose the auth type and a configured boolean,
never credential values. Added the authentication columns in a separate
migration and documented the required allowlist/key settings. Unauthenticated
Prometheus sources continue to work without an encryption key.

**Verification:** Prometheus-focused source tests: 4 passed. Source suite:
32 passed, 1 skipped. Tests confirm encrypted bearer/basic credential storage,
secret-free responses, and rejection when the encryption key is missing.
Full suite after M1.1/M1.2: 94 passed, 1 skipped.
Pylance diagnostics for changed application files are empty apart from two
existing unused `_project` warnings in `source_service.py`. No live database
migration or Prometheus connection was run.

#### M1.3 — Owner-only Prometheus connection validation

**Status:** Implemented; awaiting review.

**Implemented:** Added an owner-only `POST .../prometheus/validate` route that
checks the configured endpoint's `/-/ready` path with stored bearer/basic
authentication. Requests use the existing exact-host allowlist, a bounded
timeout, disabled redirects, and no environment-proxy inheritance. Only the
HTTP status is used; upstream response bodies and credentials are not exposed.
The source stores `not_checked`, `connected`, or `unavailable` plus the last
check timestamp. Updating configuration resets that status. Added a database
migration, source response fields, timeout setting, and setup documentation.
This confirms readiness and configured authentication, not permission to query
metrics.

**Verification:** Prometheus-focused source tests: 5 passed. Migration head
reports the new revision, and the migration compiles when targeted directly.
Source suite: 33 passed, 1 skipped. Full suite after M1.3: 96 passed,
1 skipped; the skipped PostgreSQL row-lock concurrency test requires
PostgreSQL. No live Prometheus endpoint or database migration was run.

### M2 — Bounded, read-only Prometheus query client

**Status:** Implemented; automated and live Docker verification complete.

**Implemented:** Added a reusable async Prometheus HTTP client for instant
`/api/v1/query` and range `/api/v1/query_range` requests, plus read-only
`prometheus.query_instant` and `prometheus.query_range` registry tools. Tools
resolve the configured Prometheus source through the existing project/source
authorization service; they accept no endpoint URL and do not persist evidence.
Existing encrypted none/bearer/basic authentication, exact host allowlisting,
redirect rejection, and disabled environment proxy behavior are reused.

**Bounds:** Defaults are a 3-second connect timeout, 15-second read timeout,
20-second total request timeout, 10-second maximum server-side query timeout,
six-hour maximum range, 15-second minimum step, 2,000 evaluation points, 100
series, 512 KiB streamed response, 4,096-character PromQL expression, and 20
queries per source per minute. Server caps override larger caller-supplied
timeout and series limits. Oversized responses are rejected while streaming;
results exceeding the series cap are locally truncated. Provider warnings and
possible series truncation are reported as partial. These limits reduce but do
not eliminate the cost of computationally expensive PromQL; Prometheus-side
resource controls remain necessary.

**Verification:** Prometheus query client and registry tests: 33 passed.
Live Docker Prometheus tool-flow test: 1 passed, including source creation,
readiness validation, instant and range queries for `up`, an empty-result
query, invalid PromQL, and a range-limit rejection. The actual `up` response
contained labeled series with value `"1"`. The M2 tools do not persist
evidence; M3 adds persistence through the combined investigation API below.

### M3 — Prometheus incident evidence in the existing investigation API

**Status:** Implemented; automated coverage added. Live API persistence is
covered by the opt-in Docker Prometheus test.

**Objective:** Add metrics criteria to the existing combined request and
persist normalized metric evidence using the current project/incident
authorization and evidence model.

**Implemented:** The combined investigation request accepts either a bounded
instant or range query. It reuses the Prometheus source authorization,
credentials, query client, rate limit, and existing `IncidentEvidence` model.
Results are deduplicated by incident, source, and normalized query hash;
success, empty, and partial results are persisted with labels, time/query
metadata, retrieval timestamp, and provenance. Failures are reported as
unavailable and are not represented as persisted evidence. `prometheus_metrics`
is available through the existing evidence API and evidence-reading tool.

**Acceptance:** Existing API fields and status semantics remain compatible;
same-project source and incident are enforced; query hash deduplicates
evidence; result includes query, time range, labels, retrieval time, and
provenance; partial/unavailable outcomes are explicit; existing source,
incident, Loki, Tempo, Docker, and GitHub regression tests pass.

The initial metric signals remain caller-selected; OpsPilot does not infer a
service, metric, or deployment label. Useful examples include `pg_up`,
application database-failure counters, and build/deployment metadata, with
caller-supplied time ranges matched to the incident or alert.

### M4 — Deterministic incident context and cross-source correlation

**Status:** Complete; live three-source acceptance passed on 2026-11-05.

**Objective:** Build a model-independent context from incident time, provider
labels, service/environment/deployment identifiers, and persisted evidence.
Select only safe, supported queries; never invent service/container/repository
identifiers.

**Implemented and verified:** The authenticated incident context endpoint
summarizes persisted evidence, bounded timeline events, source coverage, metric
series and transitions, and deterministic correlations. Timeline events
reference persisted evidence. The full backend suite passed 143 tests with
2 skipped. A live Grafana alert reached OpsPilot; an authenticated investigation
persisted nonempty Prometheus, Loki, and Tempo evidence for a fresh controlled
operation. The subsequent authenticated context response reported an exact
`shared_trace_id` correlation between the Loki log and Tempo spans. See the
2026-11-05 acceptance record in `docs/M4_ARCHITECTURE_DECISION.md`; it
supersedes the earlier historical-window partial result.

**Acceptance:** Correlation decisions are deterministic and testable; mismatched
labels, missing context, and conflicting deployment metadata are surfaced;
each timeline item points to source evidence and observed time.

### M5 — Durable investigation runs and bounded execution

**Status:** Synchronous durable-run implementation and isolated migration
validation complete; configured application database migration remains pending.

**Objective:** Persist run status, requested sources, evidence references,
timestamps, and failures so investigations can be retried and audited.
Introduce a worker only if measured request latency/reliability justifies it;
use durable PostgreSQL state rather than relying on ephemeral Redis.

**Implemented:** Existing `POST .../investigate` remains synchronous and
retains its response body. Every request now reserves a PostgreSQL run row
before provider work, persists requested criteria, integration outcomes,
evidence IDs, timestamps, terminal state, and sanitized failures, and returns
the run ID in `X-Investigation-Run-ID`. Optional `Idempotency-Key` is scoped to
user/project/incident; identical replay returns saved results without rerunning
providers, while changed criteria returns HTTP 409. Added authorized,
paginated run history and run-status endpoints. The run deadline is five
minutes; cancellation is recorded; still-running records older than six
minutes are marked interrupted on the next run/status/history request.

Automatic retries and a worker are intentionally not included: each run has
one attempt, provider timeouts already bound individual calls, and an operator
can explicitly retry by submitting a new request with a new idempotency key.
This avoids silently repeating provider work. The response remains
backward-compatible; the new response header and read endpoints are additive.

**Verification:** Focused lifecycle tests cover successful, partial, and
failed states; same-key replay; changed-request conflict; concurrent
duplicate protection; cancellation; total timeout; stale-run recovery; and
project authorization. Full backend suite: **149 passed, 2 skipped**. The new
Alembic revision was upgraded and downgraded successfully in a disposable
PostgreSQL schema; its downgrade correctly refuses to delete populated run
history. The configured application database remains at the prior revision
until its migration is explicitly applied with `alembic upgrade head`.

**Acceptance boundary:** Synchronous durability, idempotency, terminal/partial
states, bounded execution, safe cancellation, and existing response
compatibility are implemented. Automatic retry/backoff and background worker
recovery are deferred unless production latency/reliability measurements
justify them.

### M6 — Evidence-grounded AI synthesis

**Status:** Pending M5.

**Objective:** Add a provider-neutral LLM boundary that receives only
least-necessary, bounded, untrusted evidence and returns validated structured
observations, hypotheses, confidence/uncertainty, cited evidence IDs, and
recommended diagnostic next steps.

**Acceptance:** Provider failure and invalid output are explicit; every factual
claim cites available evidence; unsupported certainty is rejected; secrets
and unnecessary raw data are excluded; prompt-injection tests cover logs,
webhook content, and repository text; AI output cannot call write tools.

### M7 — User-facing investigation review

**Status:** Pending M6.

**Objective:** Expose investigation progress and evidence-backed findings in
the product UI/API. This checkout currently contains the backend; confirm the
intended OpsPilot frontend repository before selecting files.

**Acceptance:** Users can distinguish evidence, hypotheses, uncertainty,
source failures, and recommended next checks; project permissions apply to
every read; run history is traceable.

### M8 — Human-approved remediation proposals (separate project decision)

**Status:** Deferred; not required for initial investigation quality.

**Objective:** If approved later, store proposed actions separately, validate
authorization/policy, require explicit approval, and record a durable audit
trail before any action executes. Default to read-only behavior.

**Acceptance:** No action executes from model output alone; approval identity,
scope, expiry, idempotency, result, and rollback/compensation plan are
recorded; deny-by-default tests cover unauthorized and stale approvals.

### M9 — Live integration and operational acceptance

**Status:** Partial; local development-stack checks passed on 2026-11-05, but
not every integration has been exercised end to end through OpsPilot.

**Objective:** Verify configured PostgreSQL, Redis, Prometheus/Grafana, Loki,
Tempo, Docker, and GitHub integrations using a disposable test incident and
non-production data.

**Acceptance:** Each system has a documented live check, query bounds,
credential/permission requirements, evidence example, and failure behavior;
database migration is checked against an actual PostgreSQL instance; no
production outage or destructive test is performed. The current local
verification checkpoint is recorded below; it does not certify a production
deployment.

## Risks and open constraints

1. **Database-specific behavior:** The test suite uses SQLite. One concurrency
   test is skipped unless PostgreSQL is used. Migration history does not prove
   a deployed database is at the head; verify that separately before migration.
2. **External systems:** Passing mocked tests does not establish production
   service availability or deployment credentials. The local-stack live
   checks below do not certify another environment; `.env` values were not
   displayed or recorded.
3. **Request latency and retries:** Combined integration and alert-triggered
   Loki requests run in API request paths and sequentially. Slow backends can
   increase request latency; durable background execution is not present.
4. **GitHub webhook payload bound:** The GitHub webhook now streams and rejects
   request bodies larger than 1 MiB before parsing. This bounds application
   memory use for the unauthenticated webhook route; upstream and proxy limits
   should also be configured.
5. **Sensitive evidence:** Logs, alert payloads, trace attributes, and code
   diffs may contain secrets or personal data. Existing bounds/redaction are
   not a complete guarantee; define retention, access, and additional
   redaction before broad AI submission.
6. **Docker trust boundary:** A Docker socket is highly privileged despite
   read-only API operations. Keep Docker access restricted to trusted API
   operators/projects, as documented in the README.
7. **Organization migration:** The legacy organization-removal migration is
   irreversible and checks for remaining records. Do not run it against a
   database without reviewing its data preconditions and backup.
8. **Frontend ownership:** No tracked OpsPilot frontend or CI workflow was
   found in this checkout. Confirm the intended frontend/release repository
   before planning UI or deployment pipeline changes.

## Review gate and current progress

- **2026-11-05 broad local validation:** Full backend suite **143 passed,
  2 skipped**. The app started successfully; `/health` and `/health/ready`
  returned HTTP 200 with PostgreSQL and Redis ready. The live OpenAPI document
  returned HTTP 200 with 53 paths and 61 operations. `alembic current` on the
  configured local PostgreSQL reported the single migration head
  `91d6c3a8f4b2`. The real Redis rate-limit Lua path allowed two requests and
  rejected the third using a unique expiring validation key. The opt-in live
  Prometheus integration test passed against the local Prometheus service.
  Prometheus, Loki, Tempo, and Grafana readiness endpoints returned HTTP 200;
  the Docker daemon answered a read-only `docker info` request. Git ignores
  the root `.env`; secret values were not printed or recorded.
- **Repeat verification before M5:** The full suite passed **143 passed,
  2 skipped**. The separately enabled live Prometheus tool-flow test passed
  (**1 passed**). Read-only `alembic check` reported no pre-M5 schema drift.
  The running API returned HTTP 200 for readiness and OpenAPI (53 paths,
  61 operations). No repository lint/type-check configuration or installed
  `ruff`/`mypy` command was available.
- **2026-11-05 authenticated Docker/auth checks:** Using an existing project
  membership and enabled Docker source, an ephemeral in-memory access token
  exercised the protected route: missing credentials returned HTTP 401;
  authenticated Docker validate and container-list calls returned HTTP 200;
  the read-only investigation of the existing
  `portfolio-opspilot-test-api` container returned `success`. No incident ID
  was supplied, so no evidence was persisted; container logs and credentials
  were not printed. The real Redis OTP Lua challenge accepted its generated
  code and rejected/locked after three invalid attempts using unique synthetic
  email identifiers; no email was sent and no database record was created.
- **User acceptance:** The user confirmed that end-to-end registration/login,
  real email delivery, and the remaining deployment-specific workflows are
  working and asked to leave them unchanged. These were not independently
  re-tested in this validation pass; this records the user's acceptance, not
  new live verification. Previously recorded live GitHub retrieval and M4
  Prometheus/Loki/Tempo evidence remain bounded to those specific flows.
- **Gate:** The user accepts the remaining checks as working. M4's live
  three-source acceptance and the broader local checks are complete; M5 may
  proceed. This is not a claim that every production environment was
  independently audited.
- **Completed:** Phase 1 source inspection, safe isolated test baseline,
  migration graph inspection, data-flow tracing, capability classification,
  roadmap draft, and Stage 1.1/1.2/1.3/1.4/1.5 registry, Loki, Tempo, Docker,
  GitHub, and incident-evidence tool adapters.
- **Completed:** M2 bounded, read-only Prometheus instant/range query client,
  registry tools, automated tests, and live verification against the local
  Docker Prometheus instance.
- **Completed:** M3 Prometheus incident evidence in the combined investigation
  API, with query-hash deduplication and evidence-reader support.
- **Completed:** M4 deterministic context and correlation implementation,
  automated tests, live authenticated investigation, and context retrieval
  with successful Prometheus, Loki, and Tempo evidence. The context reports
  the exact shared trace ID between Loki and Tempo; see the 2026-11-05
  acceptance record in `M4_ARCHITECTURE_DECISION.md`. GitHub remains an
  on-demand supplemental integration.
- **Implemented, migration pending:** M5 durable synchronous investigation
  runs. The migration is verified in isolation but is not yet applied to the
  configured application database; see the milestone section for retry and
  worker boundaries.
- **Not started:** M6 AI planning/synthesis; frontend investigation review.

**Next step:** Apply the M5 migration in the intended environment, smoke-test
the persisted run API there, then proceed to M6 when separately approved. The
user makes all commits and pushes.
