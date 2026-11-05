# M4 architecture decision: incident context and evidence correlation

## Decision

Build an authenticated, read-only incident-context endpoint from existing
`Incident`, `IncidentEvidence`, source-event, and project-source records.
Construct a bounded timeline, exact-identifier relationships, and evidence
gaps on demand. Keep provider payloads unchanged in the existing evidence
records; return references and compact normalized metadata from the context
endpoint. Do not persist derived context or relationships in M4.

This reuses the current evidence ledger and authorization boundary, avoids
provider calls during context construction, and leaves durable runs and agent
orchestration for later milestones.

## Existing implementation findings

The actual evidence write path is integration-specific and already persists
provider-specific original and normalized JSON:

| Evidence type | Available identifiers and timestamps | Existing metadata and limitations |
|---|---|---|
| `prometheus_metrics` | Source ID; metric labels; instant evaluation time or range sample timestamps | Original PromQL/results; normalized query, result/sample counts, warnings, partial/truncated flags, source endpoint and retrieval time. Samples are observations, not causal events. |
| `loki_logs` | Source ID; entry nanosecond timestamp and labels | Original query, selector and log entries; normalized range, query hash, count and retrieval time. Entry lines are untrusted data. |
| `trace_spans` | Source ID; trace/span IDs, service name and span start/end nanoseconds | Original query/traces; normalized query criteria/range, trace/span counts, query hash and retrieval time. Tempo timestamps have nanosecond source precision. |
| `docker_investigation` | Source/project/container IDs; Docker event seconds/nanoseconds; container started/finished timestamps | Normalized collection time, query window, component evidence, unavailable components, errors, findings and provenance. Collection time is not a container event time. |
| `github_context` | Repository/event/run IDs and commit SHA | Original workflow, jobs, commit, files and logs; normalized retrieval time and partial/truncation flags. Workflow payloads may lack a complete start/end time. |
| Alertmanager/Grafana notifications | Alert fingerprint, labels, `startsAt`/`endsAt`; associated alert row has receipt times | Original provider alert and normalized labels/status/severity. Notification evidence has persistence time but no normalized retrieval time. |
| `webhook_payload` | Source-event ID; associated `SourceEvent.received_at` | Original payload and normalized incident fields. Arbitrary webhook payloads do not guarantee an occurrence timestamp. |
| `manual_report` | Incident and evidence IDs | Original submitted report and normalized title/type/severity. No independent occurrence timestamp is supplied. |

`IncidentEvidence.created_at` means persistence time, not necessarily
observation time. Existing tool evidence references currently label that time
as `observed_at`, which is semantically misleading. There is no existing
context builder, unified timeline, evidence relationship model, or durable
record of failed integration executions.

## External research

Research inspected three relevant ecosystems, relying on official
documentation and source:

* **Akmatori** — its [architecture documentation](https://akmatori.com/docs/architecture)
  describes assigned tools behind a gateway and scoped investigation context.
  Repository inspection verified gateway-mediated tool execution and an
  incident correlator that bounds candidates and attempts deterministic
  fingerprint matching before its optional model-based branch. Its event model
  keeps source identity and separate received/occurred times.
* **Grafana Tempo/Grafana** — inspected Tempo query implementation uses
  explicit time ranges and a maximum-series stopping condition. Grafana's
  [trace correlations guide](https://grafana.com/docs/grafana/latest/datasources/tempo/configure-tempo-data-source/trace-correlations/)
  documents trace-to-log links using service identity and trace IDs as query
  filters; it cautions against high-cardinality trace IDs as Loki stream
  labels. This is a Grafana correlation pattern, not a feature implemented by
  Tempo's query code. OpsPilot extracts trace IDs only from explicit fields
  in JSON-formatted Loki log lines, not from arbitrary free-form text.
* **OpenTelemetry** — the [Trace API specification](https://opentelemetry.io/docs/specs/otel/trace/api/)
  defines trace/span context, span start/end times, attributes, events and
  nanosecond-capable epoch timestamps. The Collector batch processor also
  demonstrates bounded processing by batch size and timeout; it is not an
  incident timeline or evidence store.

These are verified patterns, not a claim that the projects share one incident
context contract. In particular, the inspected Tempo range path did not verify
a general partial-result contract.

| Concern | Research pattern | OpsPilot decision |
|---|---|---|
| Evidence provenance | Akmatori preserves source identity and event identity. | Keep current evidence IDs, source/event IDs and original payloads; context items link to those records. |
| Time semantics | Akmatori separates occurred and received times; OTel spans carry start/end times. | Preserve source timestamp and timestamp type separately from retrieval and evidence persistence. |
| Trace/log correlation | OTel trace IDs and Grafana trace-to-log query links. | Use exact trace IDs in labels or structured JSON log fields, and exact service labels; do not make trace IDs Loki index labels or infer them from free-form text. |
| Bounds | Tempo bounds range results; Akmatori bounds candidates; Collector bounds batches. | Bound evidence rows, timeline events, and emitted relationships in the request path. |
| Orchestration | Akmatori routes tool work through a constrained gateway. | Keep the current static registry and server-side authorization; M4 makes no provider calls and adds no agent framework. |

## Alternatives considered

* **Graph database or persisted relationship table:** rejected. M4 relationships
  are deterministic views over bounded, already-persisted evidence; no query
  or scale requirement justifies another store or migration.
* **Persist normalized context on every investigation:** rejected. Existing
  evidence remains authoritative; derived context can become stale as evidence
  is added. Recompute it on demand until M5 introduces explicit run records.
* **Retrieve providers while constructing context:** rejected. This would mix
  evidence ingestion with context reads and make API availability depend on
  all upstream providers.
* **String similarity, inferred causality, or numerical confidence:** rejected.
  They are not auditable from the fields currently stored and could present
  speculation as fact.
* **Akmatori's model-based candidate matching:** rejected for M4, which must be
  deterministic and model-independent.

## Implemented data flow

```text
authenticated GET /projects/{project_id}/incidents/{incident_id}/context
  -> existing get_project_incident authorization
  -> bounded incident evidence query (incident_id-scoped)
  -> project-scoped source coverage aggregation and batched event/alert lookups
  -> parse known source timestamp formats without mutating evidence
  -> build timeline + exact-ID relationships + coverage/gaps
  -> return typed context with references to existing evidence
```

The response carries incident fields, bounded evidence references (100),
timeline observations (200), exact-ID relationships (200), the provider query
window and retrieval time when persisted, integration configuration/evidence
coverage, and explicit gaps/partial/truncation flags. It does not expose
original provider payloads, endpoints, or credentials. Full source content
remains available through the existing incident evidence API/tool. Correlation
types are exact trace ID, service, instance, full commit SHA, workflow run ID,
container ID, and repository identity matches; no temporal-only relationship
is emitted.

Prometheus range results are represented by one timeline summary per series,
with sample count, first/last sample references and values, and the number of
observed value changes. Each detected transition (including a real `1` to `0`
change) has its own event and sample index references. Raw samples remain
unchanged in the referenced evidence. Summaries and transitions have separate
bounds and explicit omission flags.

When the timeline exceeds its limit, selection first preserves incident and
alert lifecycle events, then metric transitions and container/workflow
transitions, then other observations. Within a priority, events with timestamps
are preferred and newer events are selected first; the retained set is then
sorted chronologically with evidence ID and event ID as stable tie-breakers.
Thus the response is repeatable and avoids allowing old bulk observations to
hide recent changes, while `timeline_truncated` and metric-specific flags make
omissions visible.

Correlations require different source identities, exact supported identifiers,
and exclude common placeholder labels such as `Grafana` and
`unknown_service`. More specific identifier kinds (trace ID, full commit SHA,
workflow run, container ID, repository, service, then instance) are prioritized
before the relationship cap. Each relationship includes its method, evidence
references, explanation, and the source-time range available for each
evidence record. This establishes shared metadata, not causation.

Source coverage counts evidence linked directly to an incident source and
evidence linked through its provider alert or webhook source event. It does
not claim an execution history. Successful empty queries persist evidence
with zero results; failed provider attempts do not persist evidence. The
investigation response distinguishes `not_requested`, `not_configured`,
`empty`, `unavailable`, `success`, and `partial` for the execution being
returned, but those statuses are not durably associated with a run. A later
context read therefore cannot infer whether an unavailable integration was
attempted or whether an integration with no evidence was skipped.

## Correlation and timestamp rules

* Normalize explicitly zoned ISO timestamps and known numeric epoch formats to
  UTC while preserving each original value and timestamp meaning. Missing,
  invalid, or timezone-naive provider timestamps remain unnormalized and are
  surfaced as gaps; they are never guessed to be UTC.
* Database timestamps use the timezone-aware SQL column contract. The SQLite
  test backend may strip timezone metadata; this adapter behavior is identified
  as such rather than generalized to provider timestamps.
* Build timeline observations from actual source event times: alert start,
  Loki entry, Tempo span, Prometheus sample, Docker event/state transition,
  GitHub run, or source-event receipt. Keep retrieval and persistence times
  separate. Do not fabricate event times from evidence persistence.
* Emit relationships only for exact, documented identifiers: valid trace ID,
  exact service/instance label values, exact container IDs, repository/run
  identity, and full commit SHAs. Temporal proximity alone does not establish
  a relationship or cause.
* Keep original evidence untouched and mark returned provider-derived fields
  as untrusted data.

## Security, performance, and compatibility

* The context endpoint reuses project and incident authorization and filters
  evidence by the authorized incident ID. It returns no credentials or source
  endpoint/auth configuration.
* Avoid N+1 queries: fetch evidence with one bounded query and batch lookup
  linked sources/events. Never call Prometheus, Loki, Tempo, Docker, or GitHub
  from the context endpoint.
* Bound evidence rows, emitted timeline events, and relationships. Return a
  truncation indicator and evidence gaps when limits are reached.
* Keep all existing incident and evidence endpoints unchanged. The new
  endpoint is read-only and requires no schema migration.
* Existing persisted evidence does not record every failed or skipped
  integration execution. Context can state configured sources and which
  integrations have evidence, but cannot infer that an unrepresented
  integration was attempted or unavailable. M5 run records are needed for
  that history.

## Validation plan

Test timestamp parsing for UTC, offsets, epoch seconds/nanoseconds, missing,
invalid and timezone-naive values; test exact trace/service/instance/commit/run
matching and non-matching similar values; verify timeline order, tie stability,
unknown timestamps, evidence gaps, limits and no source mutation. Exercise the
authenticated API for member access, outsider denial, cross-project and
cross-incident isolation, and secret omission. Run existing M1-M3 tests and
use only already-running local integrations for any live verification.

## M5/M6 boundary

M4 computes a read-only deterministic snapshot from persisted evidence. M5 may
associate snapshots and evidence references with durable investigation runs;
M6 may present this typed, provenance-preserving context to LangGraph. Neither
run persistence nor LLM planning belongs in this milestone.

## Live three-source validation

Validation was performed on 2026-11-01 against the existing local
observability harness and the host-running FastAPI application. These results
are live API/provider checks, not mocked tests.

### Services and source configuration

The Prometheus, Loki, and Tempo containers
(`portfolio-opspilot-test-prometheus`, `portfolio-opspilot-test-loki`, and
`portfolio-opspilot-test-tempo`) were on Docker network
`test-harness_default`. Docker published these ports on the host: Prometheus
`127.0.0.1:9091 -> container:9090`, Loki
`127.0.0.1:3101 -> container:3100`, Tempo query API
`127.0.0.1:3201 -> container:3200`, and Tempo OTLP HTTP
`127.0.0.1:4319 -> container:4318`. The test API container
`portfolio-opspilot-test-api` was published on host port 8010. FastAPI ran on
host port 7001 during initial validation and port 7002 for the final status
check. Consequently, the source URLs use host ports, not Docker-internal
ports.

All three sources were registered through the existing source-management API
for project `519df868-5157-4a6b-b960-030ebbdea7ba`:

| Provider | Source ID | Configured URL | Validation |
|---|---|---|---|
| Loki | `c3585771-e0d4-4618-be9c-9ffcacd46a0d` | `http://localhost:3101` | Real bounded query returned log entries |
| Prometheus | `9500bc4e-e71a-48f8-b218-da1af806d5ef` | `http://localhost:9091` | Existing source validation reported connected; real queries returned series |
| Tempo | `04ecee24-aa71-4087-a443-66efc9ec5468` | `http://localhost:3201` | Existing source validation reported connected; real trace retrieved |

The stale Loki URL had been `http://localhost:3100`, which was not the
published host port. The local, ignored `.env` allow lists were updated to
include `localhost:3101` and `localhost:3201`; application code does not
hardcode these endpoints. No credentials were added to the documentation.

### Controlled telemetry and persisted evidence

The existing Portfolio test harness's protected `/api/test/contact` route
generated real telemetry. Two requests produced Prometheus counter values
`1` and `2`, Loki log lines, and Tempo traces. The second request's trace ID
was `ce724faae4208b050bf2fb8a505f5ec9`.

To reproduce with the same running harness, send its documented fixed test
payload to `http://localhost:8010/api/test/contact`, wait for the Prometheus
scrape and Loki/Tempo export, then invoke the existing investigation API
using an authorized project member. Use a range containing the operation time
and these selectors:

```json
{
  "prometheus": {
    "source_id": "9500bc4e-e71a-48f8-b218-da1af806d5ef",
    "expression": "label_replace(portfolio_test_requests_total{route=\"/api/test/contact\"}, \"service_name\", \"$1\", \"job\", \"(.*)\")",
    "start": "<UTC start>",
    "end": "<UTC end>",
    "step_seconds": 15
  },
  "loki": {
    "source_id": "c3585771-e0d4-4618-be9c-9ffcacd46a0d",
    "start": "<UTC start>",
    "end": "<UTC end>",
    "labels": {
      "environment": "local",
      "ops_pilot_test": "true"
    },
    "limit": 20
  },
  "traces": {
    "source_id": "04ecee24-aa71-4087-a443-66efc9ec5468",
    "trace_id": "<trace ID returned by the test operation>",
    "start": "<UTC start>",
    "end": "<UTC end>",
    "limit": 5
  }
}
```

Submit the body to
`POST /projects/519df868-5157-4a6b-b960-030ebbdea7ba/incidents/e70c07f2-9964-4a8a-b211-d1f96e587f76/investigate`,
then inspect the returned evidence IDs and call the matching `/context` GET.

The existing incident used for the API investigation was
`e70c07f2-9964-4a8a-b211-d1f96e587f76` in the same project. Its attached
Grafana alert is historical and identifies `demo-app`; Grafana had no active
alert rules. Its labels (`environment=local`,
`ops_pilot_test=true`) were used as the bounded Loki selector. The synthetic
`portfolio-api` operation did not trigger that alert, and no new alert or
incident was fabricated. The evidence below was retrieved and persisted
against the existing incident through the supported investigation API, but
the alert itself is not evidence that the new operation caused that incident.

| Provider | Persisted evidence | Actual data |
|---|---|---|
| Prometheus | `d80696da-c404-4cae-a5e1-93adab186308` | One real range series, 15 samples |
| Loki | `4a3c77f4-f3c8-4762-9bcf-2395a19bb19b` | Two real entries; one log line contains the second request's exact trace ID |
| Tempo | `c933af11-18fb-44de-8e10-845a135307d1` | One real trace, six spans, trace ID `ce724faae4208b050bf2fb8a505f5ec9` |

Prometheus was queried with
`label_replace(portfolio_test_requests_total{route="/api/test/contact"}, "service_name", "$1", "job", "(.*)")`.
This explicitly maps the real scrape `job=portfolio-api` label to
`service_name=portfolio-api`; it does not add trace IDs to metric evidence.
A later bounded range query persisted evidence
`479dc328-690b-4232-8856-457feb343d95` with 18 original samples and a real
`1` to `2` value transition. The raw samples remain in the evidence record;
the context exposes one series summary and a separate traceable transition
event.

Tempo's live OTLP JSON represented trace, span, and parent-span IDs as
base64. The adapter now requests `Accept-Encoding: identity` (Tempo's
negotiated gzip response was invalid for the observed endpoint) and normalizes
valid base64 OTLP IDs to lowercase hexadecimal while preserving valid
hexadecimal IDs. The retrieved six spans retained their trace/span/parent
relationships and source timestamps. A regression test covers this live
provider representation.

### Correlation and context API results

The context API returned `shared_service=portfolio-api` relationships between
the primary Prometheus, Loki, and Tempo evidence. It also returned a stronger
exact trace relationship: `shared_trace_id=ce724faae4208b050bf2fb8a505f5ec9`
between Loki evidence
`4a3c77f4-f3c8-4762-9bcf-2395a19bb19b` and Tempo evidence
`c933af11-18fb-44de-8e10-845a135307d1`. The ID is an explicit `trace_id`
field in a JSON-formatted Loki log entry and the normalized Tempo trace ID;
the respective observation ranges overlap at the trace's actual timestamp.
Prometheus evidence `d80696da-c404-4cae-a5e1-93adab186308` has the exact
`service_name=portfolio-api` label added by the documented PromQL
`label_replace`, linking it to the other two providers by service identity.
No temporal-only relationship was emitted and these correlations do not claim
causation.

The implementation previously correlated trace IDs from Loki labels only.
That missed the real structured `trace_id` in the preserved log line. The
context builder now parses bounded JSON log lines (at most 64 KiB), accepts
only explicit `trace_id`, `traceId`, `traceID`, or `trace.id` fields whose
values are valid nonzero 16- or 32-character hexadecimal IDs, and normalizes
them to lowercase. It does not scan arbitrary text or execute/interpolate log
content. A unit regression covers exact match, case normalization, malformed
or suffixed values, free-form text, and all-zero IDs.

The final context GET for the incident returned 16 evidence references, 44
timeline events, and 11 relationships. The configured source coverage was
Loki 4 evidence rows, Prometheus 7, and Tempo 2; these counts include empty
query records and prior evidence, so they are not counts of successful
queries. Timeline truncation was false. Every timeline and correlation
reference resolved to an evidence ID belonging to the requested incident.
The metric transition event showed `1` to `2`; timestamps were normalized
with UTC `Z` offsets; provider content was marked untrusted. Repeated context
GETs before the final edge-case queries returned identical timeline and
correlation arrays.

### Empty, partial, missing, and unavailable sources

| Case | Live result |
|---|---|
| Prometheus valid query with no matching series | `empty`, evidence `0341f3b6-0204-4497-8799-7e6e7fc730e2`, zero series/samples; context contained persistence/retrieval events but no metric-sample event |
| Prometheus `up` query with `series_limit=1` | `partial`, evidence `8cb50639-82c1-433b-b9f3-3fcca13b2704`, one returned series/sample, `partial=true`, `truncated=true` |
| Loki 30-second bounded query with no recent entries | `empty`, evidence `ffeab7e2-7e83-4c57-9501-7f1353444ebd` |
| Tempo query for valid-format, absent trace ID | `empty`, evidence `905ffe1c-e43c-468a-92c0-320193491805` |
| Loki container stopped during a combined query | Loki `unavailable` with no evidence ID; Prometheus still `success`; aggregate `partial`. Loki was restarted and returned ready after its startup grace period. |
| Tempo container stopped during a combined query | Tempo `unavailable` with no evidence ID; Prometheus still `success`; aggregate `partial`. Tempo was restarted and returned ready. |
| Loki source ID absent from project `bee47bdb-7a64-4922-a017-66ace3e21a91` | `not_configured`, no evidence ID; using a source ID from another project also did not expose or retrieve that source. |

The investigation response was corrected to report an omitted Prometheus query
as `not_requested`, a missing project-scoped source as `not_configured`, a
successful no-data query as `empty`, and provider/query failures as
`unavailable`. This is response-time status only; failed attempts are still
not recorded in a durable run history. The context for the second project
showed one configured Prometheus source and one existing Prometheus evidence
row, plus a manual report with no supported identifier in common with the
metric evidence. It had no Loki or Tempo configuration and returned zero
correlations. This verifies that no relationship was inferred from unrelated
evidence or time proximity alone.

### Validation commands and remaining acceptance gap

The focused command is:

```sh
PYTHONPATH=. myenv/bin/pytest -q \
  tests/test_incident_context.py tests/test_incidents.py tests/test_sources.py
```

The focused context, incident authorization/isolation, and source/provider
tests include mocked provider cases; those are not live service tests. Live
service and API results above were obtained separately from the real
Prometheus, Loki, Tempo, and test harness containers.

The focused command completed with **53 passed, 2 skipped**. The complete
backend suite also passed:

```sh
PYTHONPATH=. myenv/bin/pytest -q
```

Result: **141 passed, 2 skipped**. The tests cover deterministic timeline
ordering/truncation, exact versus absent identifiers, project authorization,
and provider-adapter behavior. No test in those pytest runs was represented as
a live provider test; the live API/provider checks are the separate results
above. Existing API tests exercised outsider denial and project isolation.
For live checks, the seeded database had no user outside both test projects,
so a live outsider token was unavailable; live source ownership was checked
by attempting to use the other project's source ID and receiving no evidence.
The two skips were the opt-in Docker Prometheus test
(`OPSPILOT_RUN_PROMETHEUS_INTEGRATION=1` was not set) and the PostgreSQL
row-lock concurrency test, which skips on the SQLite test backend. A separate
focused run of the status distinction, combined investigation, partial
evidence, and Tempo normalization regressions completed with **4 passed**.

Live Prometheus, Loki, and Tempo retrieval, metric transition summarization,
exact trace-ID and service correlations, empty/unavailable cases, and API
reference integrity were demonstrated. Strict end-to-end incident causality
remains unverified: the incident was created by a historical Grafana alert
whose `service_name` is `demo-app` and whose start time predates the
`portfolio-api` test operation. The API investigation then attached real
provider evidence from the separate test operation to that incident. No
Grafana rule was configured to create an alert for the controlled operation.
Therefore the implementation and provider acceptance checks pass, but the
full controlled-incident acceptance remains **PARTIAL PASS** until a genuine
scenario-matched alert/incident is generated and investigated. The structured
trace-ID correlation fix itself is now implemented and verified against the
persisted real records.

As a follow-up check, the running Grafana 11.2.0 provisioning API was queried
using its locally configured administrator account: it contained no alert
rules and only the default email contact point, so there is no existing
webhook delivery path to OpsPilot. The only OpsPilot API exposed on the
configured test port was the Portfolio test harness, not the authenticated
incident API. The OpsPilot application server was not running, and its
source-creation and incident endpoints require an authenticated project user.
Consequently, no alert rule, contact point, source credential, or incident was
created or changed during this follow-up; doing so without an authorized
OpsPilot session would bypass the application's authentication boundary.

### 2026-11-02 live acceptance retest

The separate Portfolio test harness repository was inspected and its local
test token was found to be present in both its ignored `.env` and the API
container, but only five characters long. It was rotated to a cryptographically
random URL-safe token with 32 bytes of entropy; the local `.env` remains
Git-ignored and its Windows ACL was restricted to the current user. The
container was recreated without stopping or changing the database or
observability services. Requests without a token and with an invalid token
returned HTTP 401. With the configured token, the synthetic harness request
returned HTTP 201 and executed one real insert into the healthy test database.

The request generated trace ID
`513191013ac0293895c0e63003a4e45b`. Prometheus returned a positive
`increase(portfolio_test_requests_total{route="/api/test/contact"}[5m])`
value. Loki returned the corresponding structured `test_submission_stored`
entry with that exact trace ID. Tempo returned the trace with six spans; its
OTLP JSON encoded the trace ID as base64
`UTGRATrAKTiVwOYwA6TkWw==`, which decodes to the same hexadecimal ID. Thus
the fresh request proved live test-token authentication and exact
Prometheus/Loki/Tempo telemetry correlation at the provider level.

Grafana had one active test rule and a webhook contact point targeting
`http://host.docker.internal:7000/webhooks/sources/5fe21297-9899-4220-b965-529763d79af2/grafana`.
The alert label routed to that contact point, and Grafana successfully reached
the OpsPilot endpoint. Grafana logs show its webhook was rejected with HTTP
401 Unauthorized. The target source exists in project
`bee47bdb-7a64-4922-a017-66ace3e21a91`, is enabled, and is a Grafana source;
the contact point is configured to send a nonempty Bearer credential.
However, the credential cannot be compared to the source's stored hash because
the raw value is returned only once at source creation/rotation. Therefore the
most likely remaining problem is a stale or incorrect contact-point
credential (or a header delivery mismatch); the 401 response alone cannot
distinguish those causes. No new incident or provider alert was persisted for
this controlled request, so no new incident-context response or
incident-associated three-source evidence can be claimed.

The authenticated context endpoint also returned HTTP 401 when called without
an OpsPilot user access token, confirming the live authorization boundary. A
valid project-owner access token was not available to the validation process,
so the webhook source credential was not rotated programmatically and
authentication was not bypassed. The complete backend suite was rerun:
**141 passed, 2 skipped**. This does not turn the failed live webhook delivery
into an end-to-end pass. M4 remains **PARTIAL PASS** until the project owner
rotates the credential for source
`5fe21297-9899-4220-b965-529763d79af2`, updates the Grafana contact point's
Bearer credential, and verifies that the firing alert creates/updates an
incident which is then investigated through the authenticated context API.

### 2026-11-02 live webhook recovery retest

After the owner reported correcting the Grafana contact configuration, the
OpsPilot API was started on port 7000 and its live readiness endpoint returned
HTTP 200 with PostgreSQL and Redis ready. The harness and observability
containers were already running. A single documented synthetic operation
returned HTTP 201 and generated trace ID
`918024b2d3b62e5f8cfe509b854c4118`.

Live provider checks found:

- Prometheus returned one `portfolio_test_requests_total` series for
  `route="/api/test/contact"` and `outcome="success"` with current value `6`;
  the bounded five-minute increase query returned a positive value.
- Loki returned one matching `test_submission_stored` entry. The webhook
  automatically persisted it as evidence
  `d2201b0c-93ff-4267-9181-6fd1fa2b7eb8`; that persisted entry contains the
  same trace ID.
- Tempo returned six spans for the requested trace ID. Its OTLP JSON encodes
  IDs as base64; decoding them produced the same trace ID, six distinct span
  IDs, five valid parent links, timestamps, and resource attribute
  `service.name="portfolio-api"`.

Grafana successfully delivered the alert to the configured OpsPilot webhook:
the live API access log recorded HTTP 200. This created incident
`21255391-41c0-4fd1-b132-8c19f85450f9` in project
`bee47bdb-7a64-4922-a017-66ace3e21a91`. Its persisted evidence currently
contains `grafana_notification` and `loki_logs`. Enabled Prometheus, Loki,
Tempo, and Grafana sources exist in this same project, and the persisted Loki
query used incident labels `job="portfolio-api"` and
`service_name="portfolio-api"`.

The authenticated POST `/investigate` and GET `/context` routes both reject
requests without an OpsPilot user access token with HTTP 401. No project-user
token was available to this validation process, so the combined investigation
API was not invoked with authorization. As a result, Prometheus and Tempo
evidence were verified against their live provider APIs but were **not**
retrieved and persisted through OpsPilot's investigation endpoint for this
incident; no incident context response or API-produced cross-source
correlation is claimed. The exact Loki/Tempo trace-ID match is provider and
persisted-Loki evidence, not proof that the incident context API emitted that
correlation.

Validation on this retest: focused context/incident/source tests,
**53 passed, 2 skipped**; full backend suite, **141 passed, 2 skipped**.
The tests are automated tests (provider behavior is mocked where applicable);
the Prometheus, Loki, Tempo, Grafana webhook, and harness checks above are
live checks. M4 therefore remains **PARTIAL PASS**. To finish acceptance,
invoke `/investigate` for the incident above with the same-project source IDs
and then retrieve `/context` using a valid project-member access token. Verify
that `prometheus_metrics`, `loki_logs`, and `trace_spans` are persisted and
that the context API reports the exact shared trace-ID correlation with valid
evidence references.

### 2026-11-05 authenticated investigation result

The project owner ran both authenticated endpoints for the same incident.
The investigation request completed with aggregate status `success`, but its
per-source results were:

| Integration | Result | Persisted result |
|---|---|---|
| Prometheus | `empty` | Evidence `1940030d-ca74-42d2-bb00-e89f63316d12`; zero series/samples |
| Loki | `success` | Evidence `528c8fea-18c6-4554-a068-a82f8c26fdfc`; one log entry |
| Tempo | `empty` | Evidence `6e71c476-ca75-446f-94a7-6bbf7c5b9482`; zero traces/spans |

The request used the Nov 2 historical time window and trace ID. The API was
called on Nov 5, so the Prometheus and Tempo results do not demonstrate
retrieval of the controlled event; the old trace was no longer returned by
Tempo and the historical Prometheus range was empty. Loki still returned the
persisted log containing trace ID
`918024b2d3b62e5f8cfe509b854c4118`.

The context response includes all three evidence record types, but its
Prometheus and Tempo records describe empty results, not retrieved metrics or
spans. It reports `shared_service="portfolio-api"` correlations between the
Grafana alert and Loki evidence. It does **not** report a
`shared_trace_id` correlation, because the incident's Tempo evidence contains
no spans. A common service label is not a substitute for the exact shared
trace identifier required by the live acceptance scenario.

The aggregate investigation status `success` means the requested integrations
completed without an unavailable/error result; it does not mean each returned
data. The per-integration statuses and evidence counts are authoritative for
whether matching data was found. The context source-coverage counts count
persisted evidence records, including records whose status is `empty`; inspect
each evidence status rather than interpreting a nonzero count as nonempty
provider data.

**At this point in the acceptance history, M4 remained PARTIAL PASS.**
Authentication, project ownership, live Grafana
delivery, persistence, the context response, and the explicit empty-result
states are now verified. The final live acceptance requirement is still a
fresh controlled operation followed promptly by investigation using its
current time range and trace ID, with nonempty Prometheus metrics, Loki log
entry, and Tempo spans persisted for the same incident and an exact
`shared_trace_id` correlation in context. No implementation defect is
established by these results: they are consistent with querying expired
historical data.

### GitHub on-demand integration alignment

The chosen GitHub behavior is explicit, on-demand inclusion rather than
automatic incident attachment. A project owner installs the GitHub App and
connects a repository; the signed `/webhooks/github` endpoint stores completed
failed or unexpected workflow-run events. An authorized project member selects
the connected GitHub repository ID and stored event ID in the existing
incident `POST /investigate` request. The combined investigation persists
`github_context` evidence on that incident. The context builder can correlate
that evidence with incident evidence using exact workflow-run IDs, full commit
SHAs, or repository identities; it must not infer a match from time or generic
labels alone.

Added regression coverage exercises the combined authenticated investigation
route with a connected repository and stored failure event, verifies persisted
GitHub evidence, and checks an exact shared workflow-run correlation in the
context response. A separate test checks rejection of an oversized GitHub
webhook body. The webhook now streams at most 1 MiB before rejecting with HTTP
413. README setup guidance now documents the 1 MiB bound and the combined
incident flow.

Verification after these changes: GitHub/incident targeted tests passed, and
the full backend suite passed **143 tests, 2 skipped**. GitHub provider calls
in these automated tests are mocked.

A subsequent authenticated live check reused an existing genuine GitHub
failure event rather than creating a synthetic event or triggering a new run:

- Project: `bee47bdb-7a64-4922-a017-66ace3e21a91`
- Connected repository: `MohanSashank21/Portfolio` (repository ID
  `1249219668`)
- Stored event: `ab9af346-f75a-433b-84f7-435c11a5056c`
- GitHub Actions run: `41010527871`, conclusion `failure`
- Commit: `22d501c80e5ceac494e8db38bc22af94c1860eff`
- Target incident: `21255391-41c0-4fd1-b132-8c19f85450f9`
- Combined investigation response: HTTP 200, aggregate `success`,
  `github=success`, persisted evidence
  `50ae5a6c-a9b4-4383-9600-0f63798434f1`.

The persisted GitHub context identifies the Portfolio repository and failed
run; GitHub returned one job and workflow logs marked available and not
truncated. The authenticated context endpoint also returned HTTP 200 and
included this `github_context` record. It emitted no
`shared_workflow_run`, `shared_commit_sha`, or `shared_repository`
correlation for this evidence because the target incident's other evidence
does not contain those exact GitHub identifiers. This is correct for the
on-demand design: it attaches only the specifically requested event and does
not invent a cross-source match. The existing incident's Grafana/Loki evidence
does not prove a shared GitHub commit or run.

This verifies the live GitHub App retrieval and on-demand persistence flow
against an existing real failure, but does not demonstrate a newly generated
GitHub failure event or exact GitHub-to-incident correlation. GitHub remains
supplemental to M4's live Prometheus/Loki/Tempo acceptance; at this point the
live three-source gate was still open. The later fresh-acceptance section
records that gate passing.

### 2026-11-05 fresh three-source acceptance

The earlier partial-pass result is superseded by this fresh live run. The
controlled harness operation completed with HTTP 201 and trace ID
`3969986ec392325314596f5de1fcf303`. Grafana delivered the resulting firing
alert to OpsPilot with HTTP 200. It reopened/updated the existing incident
`21255391-41c0-4fd1-b132-8c19f85450f9` in project
`bee47bdb-7a64-4922-a017-66ace3e21a91`; no duplicate incident was required.

An authenticated `/investigate` request used the current time range and
project-owned Prometheus, Loki, and Tempo sources. It returned HTTP 200, and
all three provider records were persisted successfully:

| Integration | Result | Persisted result |
|---|---|---|
| Prometheus | `success` | Evidence `7cb6bc2f-0d94-4c50-ae11-c8a806f1134b`; one series and 22 samples for `/api/test/contact`, including observed counter changes |
| Loki | `success` | Evidence `2a9966c1-e542-4779-bd87-75a89bc0bf03`; one log entry containing the exact trace ID |
| Tempo | `success` | Evidence `24e1c78f-0f24-4ac6-ada9-4ec77f5aa971`; six spans for the same trace, with parent-span links |

The authenticated incident `/context` request returned HTTP 200. It reported
`shared_trace_id` value
`3969986ec392325314596f5de1fcf303` between the Loki and Tempo evidence IDs
above. Timeline evidence references resolve to records in the response; the
context was not truncated. This is the required exact identifier match, not a
service-name or timestamp-only inference.

**M4 live three-source acceptance: PASS.** The full backend suite previously
passed **143 tests, 2 skipped**; `git diff --check` also passed. The existing
test suite's PostgreSQL-dependent test remains skipped, and this live
acceptance does not establish PostgreSQL migration state, Redis Lua behavior,
or Docker daemon behavior. The context response also correctly reports Docker
as an enabled source without evidence and notes that integration execution
history is not persisted. No Docker evidence is part of the three-source M4
acceptance, and no outage or additional controlled request was triggered for
this final verification.
