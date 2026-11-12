# OpsPilot implementation plan

## Purpose and current boundary

OpsPilot is a project-scoped incident and evidence backend. The implementation
goal is an auditable investigation assistant that gathers evidence through
authorized integrations, tests hypotheses, and reports a supported conclusion
or an explicit inconclusive outcome. Any future code changes or pull requests
must remain isolated and require human approval. Automatic merge and deployment
are out of scope.

This plan is the single forward-looking implementation record. The root
[README](../README.md) remains the operational guide for running the backend
and configuring integrations.

## Existing product foundation

The current backend includes:

* FastAPI authentication and project membership, with PostgreSQL records and
  Redis-backed ephemeral authentication/rate-limit state.
* Manual incidents and generic, Grafana, and Alertmanager event intake, plus
  persisted incident evidence and alert lifecycle handling.
* Read-only Prometheus, Loki, Tempo, Docker, and GitHub integrations.
* Caller-directed combined investigations: the caller selects configured
  sources and criteria; the backend does not autonomously choose queries.
* Deterministic incident context with timeline and exact-identifier
  correlations. Correlation is not causal proof.
* Durable investigation run records, idempotency, and status/history.
* A static typed tool registry and a feature-gated, one-call Gemini synthesis
  endpoint for evidence on a completed run. Synthesis does not call tools.

One live Gemini request using only the synthetic `metric-regression` fixture
succeeded. This verifies a provider request, not report accuracy, the complete
API persistence workflow, or production readiness. The synthesis feature
defaults off. This checkout contains no LangGraph dependency, autonomous
investigation loop, or frontend.

## Architecture and safety rules

1. Keep the product a modular monolith. PostgreSQL remains the source of truth
   for incidents, evidence, and runs; Redis is for ephemeral state.
2. The model may only propose a structured action from a server-advertised
   read-only allowlist. It never chooses project identity, credentials,
   arbitrary URLs, shell commands, SQL, or write operations.
3. Authorization, strict schema validation, source ownership, rate limits,
   time/size/cost budgets, and persistence are enforced by deterministic
   backend code on every tool call.
4. Credentials stay in process configuration or encrypted source records.
   Never put credentials in prompts, tool schemas, evidence, or logs.
5. Provider output, logs, traces, workflow content, repository files, and
   benchmark fixtures are untrusted input. Preserve provenance and distinguish
   observed facts, deterministic correlations, hypotheses, and conclusions.
6. Never claim a provider action, tool result, test, or repair succeeded unless
   the corresponding operation actually completed and its result was checked.
7. Do not execute repository or generated code in the API process or through
   its privileged Docker socket. Later execution requires an isolated,
   credential-free boundary. Never automatically merge or deploy.
8. Complete and review one phase's acceptance gate before enabling work in the
   next phase. Report mocked tests separately from live integration checks.

## Phase 1 — Integration foundation

**Status: complete for this phase.** Existing integration code was audited
before adding new abstractions. A bounded live GitHub App check also passed
against an already connected repository.

### Implemented

* `app/tools/registry.py` centralizes the investigator-facing, statically
  registered tools for Prometheus, Loki, Tempo, Docker, GitHub workflow
  investigation, and persisted incident evidence.
* `app/tools/contracts.py` defines typed contexts, strict input models,
  structured results, evidence references, trust/completeness metadata, and
  descriptors. Discovery now includes both input and output schemas.
* Tool registration is fail-closed: a tool must explicitly declare itself
  read-only. Registry dispatch authorizes the project incident before
  execution and validates arguments with extra fields forbidden. Provider
  adapters separately authorize their source/repository and enforce their
  provider-specific bounds.
* Loki, Prometheus, and Tempo credentials are encrypted at rest with separate
  Fernet configuration keys; source webhook credentials are stored as hashes.
  GitHub App private-key and webhook secrets are process configuration, not
  project data. GitHub installation tokens are used for read-only API access.
* GitHub App setup state is short-lived and single-use; repositories are
  connected explicitly to projects. The integration retrieves bounded
  workflow, commit, file, and log context without exposing write operations.

### Verification and remaining acceptance

* Full automated suite: 167 passed, 2 skipped. The skips cover a live
  Prometheus integration test and PostgreSQL-only row-lock concurrency.
  GitHub/provider boundaries in the tests are mocked; this does not prove a
  live GitHub App installation works.
* The authorized live check successfully issued an installation token and
  matched connected-repository metadata from GitHub by repository ID and
  name. It did not retrieve repository content, submit a webhook, or perform
  a GitHub write. Webhook delivery remains part of Phase 2.
* Do not reveal or copy secrets to chat. Live model or provider quality is not
  implied by this integration check.
* The registry is an internal tool catalog, not a generalized registry for
  arbitrary integrations. Add new entries only alongside a real adapter,
  typed schema, authorization checks, and tests.
* The backend includes output schemas and fail-closed read-only registration,
  but budgets and per-run execution accounting belong to Phase 3's execution
  engine, not the static registry.

**Gate:** all local Phase 1 regressions pass; no credential is returned in a
tool descriptor or exposed to a model; unauthorized scope and invalid tool
arguments cannot reach a handler; provider permissions remain read-only.
Live GitHub readiness remains explicitly unverified until separately checked.

## Phase 2 — Event ingestion

**Status: implemented and locally verified, including the PostgreSQL
multi-worker concurrency test.**

* Webhook intake validates the HMAC before parsing, enforces the 1 MiB body
  limit, requires the stable GitHub delivery ID, and stores selected completed
  workflow events in a transaction. The database uniqueness constraint and
  savepoint handling make duplicate deliveries idempotent, including the
  concurrent-delivery path.
* A FastAPI-lifespan worker claims persisted events using row locks and
  `SKIP LOCKED`, records bounded attempt/status/failure state, retries
  transient processing failures with bounded exponential delay, and recovers
  expired processing leases after a restart. Existing deliveries remain
  `processed` after migration and are not replayed.
* Event-to-incident processing is one database transaction. It creates a
  project-scoped GitHub incident and compact provenance evidence, or links to
  an existing incident only when repository plus exact workflow-run ID or full
  commit SHA maps to one incident. Unique correlation rows prevent two workers
  from independently assigning the same identifier. If exact identifiers
  point to different incidents, processing creates a separate incident and
  does not take over either mapping; time proximity is never used.
* Existing persisted `github_context` evidence is backfilled into the
  correlation index. The processor does not contact GitHub; fetching workflow
  logs, files, or run details remains explicit and on-demand.
* The event list exposes processing status, attempts, safe failure category,
  and linked incident ID. The migration is additive, keeps legacy webhook
  events processed, and refuses downgrade after new incident-processing data
  has been created.

**Local verification:** GitHub ingestion/worker tests pass, including
concurrent duplicate delivery, exact and ambiguous matching, failure
visibility, retry limits, lease recovery, and process idempotency.
Incident/context regressions pass. The migration was compiled offline for
PostgreSQL and executed against a temporary SQLite schema with a
legacy-correlation backfill and downgrade check. The PostgreSQL
worker-claim/concurrent-correlation test also passed against a disposable
development database using a temporary schema that was removed afterward.
The full suite reported 175 passed and 3 skipped; skipped tests were the
live Prometheus test, the default-off PostgreSQL test, and the PostgreSQL-only
row-lock test in the unrelated Alertmanager suite.

## Phase 3 — Investigation engine

**Status: not implemented.** The current combined API is caller-directed and
the current tool registry has no model-facing planner. The deterministic
benchmark validates context projection only: it makes zero model/provider
calls and does not measure root-cause accuracy.

### Recommended implementation order

1. Extend the synthetic benchmark into an agent evaluator before enabling
   model-directed tool calls. Keep scoring labels hidden from model input;
   measure supported-cause accuracy, abstention, evidence citation validity,
   tool authorization, hard-budget compliance, and behavior under provider
   failure. Use a stub model and fake tools for deterministic tests; require
   explicit approval for any live Gemini evaluation.
2. Implement one typed, bounded investigation graph: load authorized incident
   context, select at most one discriminating read-only tool call per cycle,
   validate/execute only through `app/tools/registry.py`, record tool result
   and evidence IDs, update competing hypotheses, and stop with a cited
   conclusion or explicit inconclusive result. Enforce iteration, tool,
   latency, and model-token budgets in backend code, not in the prompt.
3. Use LangGraph for conditional routing and bounded iteration. Reuse
   `InvestigationRun` as the product lifecycle record; use a PostgreSQL
   checkpointer keyed by the run ID only for graph continuation state. Do not
   put credentials in graph state, expose direct model-to-provider access, or
   add a separate agent service. Preserve the existing synchronous
   caller-directed investigation API and keep AI investigation explicitly
   gated.
4. Add append-only step persistence only if the product needs durable
   per-step UI/history beyond LangGraph checkpoints. Keep evidence records as
   the canonical source for observations.

This choice follows the project’s actual requirement for repeated
plan→tool→evidence→hypothesis decisions and recoverable run state. It is
consistent with LangGraph’s documented distinction between fixed workflows
and dynamic agents and its checkpointing for resumption, but does not require
LangGraph Agent Server or a microservice. See the [LangGraph workflows and
agents guide](https://docs.langchain.com/oss/python/langgraph/workflows-agents)
and [persistence guide](https://docs.langchain.com/oss/python/langgraph/persistence).

**Gate:** held-out synthetic evaluation meets the agreed accuracy,
abstention, citation, authorization, failure-containment, and hard-budget
thresholds; tests prove no unapproved tool can execute and repeated calls
terminate within limits. Do not claim autonomous RCA before this gate passes.

## Phase 4 — Knowledge and memory

**Status: not implemented.** Add project-scoped repository documentation,
runbook, and historical incident retrieval only with source provenance,
authorization, freshness, retention, and untrusted-content controls.
Distinguish verified resolutions from unverified prior conclusions.

**Gate:** retrieval is project-scoped, citations resolve to source records,
stale or unverified knowledge is labeled, and injected instructions in
retrieved material cannot change tool policy.

## Phase 5 — Resolution engine

**Status: not implemented.** First propose a root-cause-linked repair plan.
Later, create changes only in a disposable isolated repository workspace with
no application credentials, host access, or default network access. Run
predefined tests there, record actual results, and require explicit
human approval for pull-request creation. No automatic merge or deployment.

**Gate:** malicious repository/build fixtures cannot reach host credentials or
the Docker socket; changes are tied to the exact base revision and validated
diagnosis; false or incomplete test results are never reported as verified;
approval is scoped, auditable, single-use, and bound to the exact patch.

## Phase 6 — Frontend

**Status: not present in this backend checkout.** Locate and confirm the
frontend repository before implementation. The review surface should expose
run progress, tool calls, evidence, hypotheses, uncertainty, source failures,
conclusions, and later repair/test outcomes. Every factual claim should link
to evidence; hypotheses must be visibly labeled.

**Gate:** project authorization is enforced for every view, partial and
inconclusive states are clear, and no UI action bypasses backend approval.

## Phase 7 — Reliability and evaluation

**Status: partial.** Focused automated tests and a deterministic synthetic
benchmark exist. One live synthetic Gemini scenario succeeded, but broad
model-quality evaluation, durable iterative-run recovery, and comprehensive
production integration acceptance remain incomplete.

Add controlled failure/restart tests, integration outage handling, security
tests, held-out investigation scenarios, and resolution accuracy measurements
before release claims. Record provider status, duration, tool count, evidence
coverage, model usage/cost, citation quality, abstention, and failure
categories without recording secrets or unnecessary raw prompts.

**Gate:** zero cross-project access, unsupported citations, unauthorized tool
calls, and hard-budget violations in the acceptance suite; performance and
quality thresholds are versioned and met on held-out scenarios. Live provider
tests require explicit approval and synthetic data unless data handling is
separately approved.

## Current change verification

The latest Phase 1 changes make read-only registration opt-in, publish the
shared typed output schema with each tool descriptor, document the GitHub App
environment variables, and add mocked tests for installation-token header
handling and requested read-only permissions. They require no database
migration. The authorized live metadata check is recorded under Phase 1.
