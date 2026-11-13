import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import (
  APIRouter,
  Depends,
  Header,
  HTTPException,
  Query,
  Response as FastAPIResponse,
  status,
)
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.exceptions import (
  IncidentNotFoundError,
  InvalidIncidentTransitionError,
  LokiIntegrationError,
  PermissionDeniedError,
  ProjectNotFoundError,
  RateLimitExceededError,
  SourceConfigurationError,
  SourceNotFoundError,
  TraceIntegrationError,
)
from app.db.database import get_db
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource
from app.db.investigation_run import InvestigationRun
from app.db.redis import get_redis
from app.db.user import User
from app.schemas.incident_context_schema import IncidentContextResponse
from app.schemas.incident_schema import (
  IncidentCreateRequest,
  IncidentEvidenceResponse,
  IncidentResponse,
  IncidentStatusUpdateRequest,
  LokiQueryResponse,
  TraceQueryResponse,
)
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  CombinedIncidentInvestigationResponse,
  InvestigationRunResponse,
)
from app.schemas.investigation_synthesis_schema import (
  InvestigationSynthesisRunResponse,
  UnsupportedEvidenceCitationError,
)
from app.schemas.source_schema import LokiQueryRequest, TraceQueryRequest
from app.services.incident_service import (
  create_manual_incident,
  get_incident_log_labels,
  get_project_incident,
  list_incident_evidence,
  list_project_incidents,
  update_incident_status,
)
from app.services.incident_investigation_service import (
  investigate_incident_integrations,
)
from app.services.investigation_run_service import (
  IdempotencyKeyConflictError,
  complete_investigation_run,
  fail_investigation_run,
  get_investigation_run,
  list_investigation_runs,
  replay_investigation_response,
  reserve_investigation_run,
  RUN_TIMEOUT_SECONDS,
)
from app.services.gemini_synthesis_service import (
  GeminiSynthesisConfigurationError,
  GeminiSynthesisError,
  GeminiSynthesisProviderError,
  GeminiSynthesisTimeoutError,
  create_gemini_client,
  synthesize_evidence,
)
from app.services.investigation_synthesis_service import (
  InvestigationSynthesisContextError,
  build_run_synthesis_input,
  claim_run_synthesis,
  complete_run_synthesis,
  fail_run_synthesis,
  synthesis_run_response,
)
from app.services.incident_context_service import build_incident_context
from app.services.loki_service import (
  LokiConnection,
  persist_loki_evidence,
  query_loki,
)
from app.services.redis_service import (
  rate_limit_gemini_synthesis,
  rate_limit_loki_queries,
)
from app.services.source_service import get_project_loki_source
from app.services.source_service import get_project_trace_source
from app.services.trace_service import (
  TraceQuery,
  retrieve_incident_traces,
)

router = APIRouter(prefix="/projects/{project_id}/incidents", tags=["incidents"])

def _incident_response(incident: Incident) -> IncidentResponse:
  return IncidentResponse(
    id=incident.id,
    project_id=incident.project_id,
    environment_id=incident.environment_id,
    source_event_id=incident.source_event_id,
    reported_by_user_id=incident.reported_by_user_id,
    source_type=incident.source_type,
    incident_type=incident.incident_type,
    title=incident.title,
    description=incident.description,
    severity=incident.severity,
    status=incident.status,
    created_at=incident.created_at,
    updated_at=incident.updated_at,
    resolved_at=incident.resolved_at,
  )


def _raise_access_error(error: Exception) -> HTTPException:
  if isinstance(error, (ProjectNotFoundError, IncidentNotFoundError)):
    return HTTPException(status_code=404, detail=str(error))
  if isinstance(error, PermissionDeniedError):
    return HTTPException(status_code=403, detail=str(error))
  raise error


def _evidence_response(evidence: IncidentEvidence) -> IncidentEvidenceResponse:
  return IncidentEvidenceResponse(
    id=evidence.id,
    incident_id=evidence.incident_id,
    source_event_id=evidence.source_event_id,
    evidence_type=evidence.evidence_type,
    incident_source_id=evidence.incident_source_id,
    original_content=evidence.original_content,
    normalized_content=evidence.normalized_content,
    created_at=evidence.created_at,
  )


def _investigation_run_response(
  run: InvestigationRun,
) -> InvestigationRunResponse:
  return InvestigationRunResponse(
    id=run.id,
    project_id=run.project_id,
    incident_id=run.incident_id,
    requested_by_user_id=run.requested_by_user_id,
    requested_integrations=run.requested_integrations,
    request_criteria=run.request_criteria,
    status=run.status,
    aggregate_status=run.aggregate_status,
    integrations=run.integration_results,
    agent_report=run.agent_report,
    evidence_ids=run.evidence_ids,
    failure_code=run.failure_code,
    failure_detail=run.failure_detail,
    attempt_count=run.attempt_count,
    synthesis_status=run.synthesis_status,
    synthesis_report=run.synthesis_report,
    synthesis_model=run.synthesis_model,
    synthesis_prompt_version=run.synthesis_prompt_version,
    synthesis_schema_version=run.synthesis_schema_version,
    synthesis_input_tokens=run.synthesis_input_tokens,
    synthesis_output_tokens=run.synthesis_output_tokens,
    synthesis_provider_attempts=run.synthesis_provider_attempts,
    synthesis_attempt_count=run.synthesis_attempt_count,
    synthesis_failure_code=run.synthesis_failure_code,
    synthesis_completed_at=run.synthesis_completed_at,
    created_at=run.created_at,
    started_at=run.started_at,
    completed_at=run.completed_at,
  )


def _synthesis_run_response(
  run: InvestigationRun,
) -> InvestigationSynthesisRunResponse:
  return InvestigationSynthesisRunResponse.model_validate(
    synthesis_run_response(run),
  )

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
  project_id: uuid.UUID,
  request: IncidentCreateRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> IncidentResponse:
  try:
    incident = await create_manual_incident(session, project_id, user, request)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  return _incident_response(incident)

@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
  project_id: uuid.UUID,
  limit: int = Query(default=50, ge=1, le=100),
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[IncidentResponse]:
  try:
    incidents = await list_project_incidents(session, project_id, user, limit)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  return [_incident_response(incident) for incident in incidents]

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> IncidentResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  return _incident_response(incident)


@router.get(
  "/{incident_id}/context",
  response_model=IncidentContextResponse,
)
async def get_incident_context(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> IncidentContextResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  return await build_incident_context(session, incident)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_status(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  request: IncidentStatusUpdateRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> IncidentResponse:
  try:
    incident = await update_incident_status(
      session,
      project_id,
      incident_id,
      user,
      request,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  except InvalidIncidentTransitionError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  return _incident_response(incident)

@router.get(
  "/{incident_id}/evidence",
  response_model=list[IncidentEvidenceResponse],
)
async def get_incident_evidence(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[IncidentEvidenceResponse]:
  try:
    evidence = await list_incident_evidence(
      session,
      project_id,
      incident_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  return [_evidence_response(item) for item in evidence]


@router.get(
  "/{incident_id}/investigation-runs",
  response_model=list[InvestigationRunResponse],
)
async def get_investigation_run_history(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  limit: int = Query(default=50, ge=1, le=100),
  offset: int = Query(default=0, ge=0),
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[InvestigationRunResponse]:
  try:
    await get_project_incident(session, project_id, incident_id, user)
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  runs = await list_investigation_runs(session, incident_id, limit, offset)
  return [_investigation_run_response(run) for run in runs]


@router.get(
  "/{incident_id}/investigation-runs/{run_id}",
  response_model=InvestigationRunResponse,
)
async def get_investigation_run_status(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  run_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> InvestigationRunResponse:
  try:
    await get_project_incident(session, project_id, incident_id, user)
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  run = await get_investigation_run(session, incident_id, run_id)
  if run is None:
    raise HTTPException(status_code=404, detail="Investigation run not found")
  return _investigation_run_response(run)


@router.get(
  "/{incident_id}/investigation-runs/{run_id}/synthesis",
  response_model=InvestigationSynthesisRunResponse,
)
async def get_investigation_synthesis_status(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  run_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> InvestigationSynthesisRunResponse:
  try:
    await get_project_incident(session, project_id, incident_id, user)
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  run = await get_investigation_run(session, incident_id, run_id)
  if run is None or run.project_id != project_id:
    raise HTTPException(status_code=404, detail="Investigation run not found")
  return _synthesis_run_response(run)


@router.post(
  "/{incident_id}/investigation-runs/{run_id}/synthesis",
  response_model=InvestigationSynthesisRunResponse,
)
async def synthesize_investigation_run(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  run_id: uuid.UUID,
  user: User = Depends(get_current_user),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> InvestigationSynthesisRunResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error

  run = await get_investigation_run(session, incident_id, run_id)
  if run is None or run.project_id != project_id:
    raise HTTPException(status_code=404, detail="Investigation run not found")
  if run.status not in {"succeeded", "partial"}:
    raise HTTPException(
      status_code=409,
      detail="AI synthesis requires a completed successful or partial run.",
    )
  if run.synthesis_status == "succeeded":
    return _synthesis_run_response(run)
  if not settings.GEMINI_SYNTHESIS_ENABLED:
    raise HTTPException(
      status_code=503,
      detail="AI synthesis is disabled by server configuration.",
    )
  api_key = settings.GEMINI_API_KEY
  if api_key is None:
    raise HTTPException(
      status_code=503,
      detail="Gemini synthesis is not configured on the server.",
    )

  try:
    serialized_context, evidence_ids = await build_run_synthesis_input(
      session,
      incident,
      run,
    )
  except InvestigationSynthesisContextError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail={"code": error.code, "message": error.message},
    ) from error

  try:
    await rate_limit_gemini_synthesis(redis, project_id, user.id)
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=429,
      detail=str(error),
      headers={"Retry-After": "3600"},
    ) from error

  claimed = await claim_run_synthesis(
    session,
    run_id,
    settings.GEMINI_SYNTHESIS_MAX_RUN_ATTEMPTS,
  )
  if not claimed:
    await session.refresh(run)
    if run.synthesis_status == "succeeded":
      return _synthesis_run_response(run)
    if run.synthesis_status == "running":
      raise HTTPException(
        status_code=409,
        detail="AI synthesis for this run is already in progress.",
      )
    raise HTTPException(
      status_code=409,
      detail="The configured AI synthesis attempt limit was reached.",
    )

  async def record_failure(
    code: str,
    provider_attempts: int | None = None,
  ) -> None:
    await fail_run_synthesis(
      session,
      run_id,
      code,
      provider_attempts,
    )

  try:
    async with create_gemini_client() as client:
      result = await synthesize_evidence(
        serialized_context,
        evidence_ids,
        api_key.get_secret_value(),
        client,
      )
    completed = await complete_run_synthesis(session, run_id, result)
  except asyncio.CancelledError:
    await record_failure("request_cancelled")
    raise
  except GeminiSynthesisTimeoutError as error:
    await record_failure("provider_timeout", error.attempts)
    raise HTTPException(
      status_code=504,
      detail="Gemini synthesis timed out; no report was produced.",
    ) from error
  except GeminiSynthesisProviderError as error:
    await record_failure(
      f"provider_http_{error.status_code}",
      error.attempts,
    )
    status_code = (
      429
      if error.status_code == 429
      else 503
      if error.status_code >= 500
      else 502
    )
    raise HTTPException(
      status_code=status_code,
      detail=str(error),
    ) from error
  except GeminiSynthesisConfigurationError as error:
    await record_failure("provider_not_configured")
    raise HTTPException(
      status_code=503,
      detail="Gemini synthesis is not configured on the server.",
    ) from error
  except UnsupportedEvidenceCitationError as error:
    await record_failure("unsupported_evidence_citation")
    raise HTTPException(
      status_code=502,
      detail="Gemini returned a citation outside this run's evidence.",
    ) from error
  except GeminiSynthesisError as error:
    await record_failure("synthesis_invalid_or_unavailable")
    raise HTTPException(
      status_code=502,
      detail="Gemini did not produce a valid evidence-grounded report.",
    ) from error

  return _synthesis_run_response(completed)


@router.post(
  "/{incident_id}/investigate",
  response_model=CombinedIncidentInvestigationResponse,
)
async def investigate_incident_integrations_endpoint(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  request: CombinedIncidentInvestigationRequest,
  response: FastAPIResponse,
  user: User = Depends(get_current_user),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
  idempotency_key: str | None = Header(
    default=None,
    alias="Idempotency-Key",
    min_length=1,
    max_length=128,
  ),
) -> CombinedIncidentInvestigationResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error

  if idempotency_key is not None and (
    idempotency_key != idempotency_key.strip()
    or any(ord(character) < 33 or ord(character) > 126 for character in idempotency_key)
  ):
    raise HTTPException(
      status_code=422,
      detail="Idempotency-Key must contain printable ASCII without whitespace.",
    )
  try:
    run, created = await reserve_investigation_run(
      session,
      project_id,
      incident_id,
      user,
      request,
      idempotency_key,
    )
  except IdempotencyKeyConflictError as error:
    raise HTTPException(
      status_code=409,
      detail="Idempotency-Key was already used with a different request.",
    ) from error

  response.headers["X-Investigation-Run-ID"] = str(run.id)
  if not created:
    if run.status == "running":
      raise HTTPException(
        status_code=409,
        detail={
          "message": "An investigation with this Idempotency-Key is still running.",
          "run_id": str(run.id),
        },
      )
    if run.aggregate_status is None:
      raise HTTPException(
        status_code=409,
        detail={
          "message": "The prior run failed before a response was finalized. "
          "Submit a new run with a new Idempotency-Key.",
          "run_id": str(run.id),
        },
      )
    return await replay_investigation_response(session, run)

  run_id = run.id
  try:
    async with asyncio.timeout(RUN_TIMEOUT_SECONDS):
      aggregate_status, integrations = await investigate_incident_integrations(
        session,
        redis,
        project_id,
        incident_id,
        user,
        request,
      )
      evidence = await list_incident_evidence(
        session,
        project_id,
        incident_id,
        user,
      )
      response = CombinedIncidentInvestigationResponse(
        status=aggregate_status,
        incident_id=incident_id,
        integrations=integrations,
        evidence=[_evidence_response(item) for item in evidence],
      )
      await complete_investigation_run(
        session,
        run_id,
        aggregate_status,
        integrations,
        [item.id for item in evidence],
      )
      return response
  except asyncio.CancelledError:
    await fail_investigation_run(
      session,
      run_id,
      "request_cancelled",
      "The synchronous investigation request was cancelled.",
      status="cancelled",
    )
    raise
  except Exception as error:
    await fail_investigation_run(
      session,
      run_id,
      type(error).__name__,
      "The investigation ended before a result could be finalized.",
    )
    raise

@router.post("/{incident_id}/loki-logs", response_model=LokiQueryResponse)
async def retrieve_loki_logs(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  request: LokiQueryRequest,
  user: User = Depends(get_current_user),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> LokiQueryResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
    source = await get_project_loki_source(
      session,
      project_id,
      request.source_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error

  labels = await get_incident_log_labels(session, incident.id)
  if not labels:
    raise HTTPException(
      status_code=422,
      detail="Incident has no Grafana or Alertmanager labels to select Loki logs",
    )
  if any(labels.get(key) != value for key, value in request.labels.items()):
    raise HTTPException(
      status_code=422,
      detail="Loki selector labels must match labels recorded on this incident",
    )
  now = datetime.now(UTC)
  if request.start > now or request.end > now + timedelta(minutes=1):
    raise HTTPException(
      status_code=422,
      detail="Loki query times cannot be in the future",
    )
  try:
    await rate_limit_loki_queries(redis, source.id)
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=429,
      detail=str(error),
      headers={"Retry-After": "60"},
    ) from error

  query = "{" + ",".join(
    f"{key}={json.dumps(value, ensure_ascii=False)}"
    for key, value in sorted(request.labels.items())
  ) + "}"
  connection = LokiConnection(
    base_url=source.loki_url or "",
    tenant_id=source.loki_tenant_id,
    auth_type=source.loki_auth_type or "none",
    auth_ciphertext=source.loki_auth_ciphertext,
  )
  source_id = source.id
  incident_id = incident.id
  await session.rollback()
  try:
    result = await query_loki(
      connection,
      query,
      request.start,
      request.end,
      request.limit,
    )
    evidence = await persist_loki_evidence(
      session,
      project_id,
      incident_id,
      source_id,
      request.labels,
      result,
    )
  except LokiIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  return LokiQueryResponse(
    status=result.status,
    entry_count=len(result.entries),
    evidence=_evidence_response(evidence),
  )


@router.post("/{incident_id}/traces", response_model=TraceQueryResponse)
async def retrieve_incident_traces_endpoint(
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  request: TraceQueryRequest,
  user: User = Depends(get_current_user),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> TraceQueryResponse:
  try:
    incident = await get_project_incident(
      session,
      project_id,
      incident_id,
      user,
    )
    source = await get_project_trace_source(
      session,
      project_id,
      request.source_id,
      user,
    )
  except (ProjectNotFoundError, IncidentNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error

  is_trace_id_query = request.trace_id is not None
  service_name = request.service_name or (
    source.trace_service_name if not is_trace_id_query else None
  )
  resource_attributes = (
    dict(request.resource_attributes)
    if is_trace_id_query
    else {
      **(source.trace_resource_attributes or {}),
      **request.resource_attributes,
    }
  )
  if request.trace_id is None and not (
    service_name
    or resource_attributes
    or request.span_attributes
  ):
    raise HTTPException(
      status_code=422,
      detail=(
        "Provide a trace ID, service name, or resource/span attributes; "
        "unfiltered trace searches are not allowed"
      ),
    )
  now = datetime.now(UTC)
  if request.start > now or request.end > now + timedelta(minutes=1):
    raise HTTPException(
      status_code=422,
      detail="Trace query times cannot be in the future",
    )
  query = TraceQuery(
    trace_id=request.trace_id,
    service_name=service_name,
    span_status=request.span_status,
    resource_attributes=resource_attributes,
    span_attributes=request.span_attributes,
    start=request.start,
    end=request.end,
    limit=request.limit,
  )
  try:
    result, evidence = await retrieve_incident_traces(
      session,
      redis,
      project_id,
      incident.id,
      source,
      query,
    )
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=429,
      detail=str(error),
      headers={"Retry-After": "60"},
    ) from error
  except TraceIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  return TraceQueryResponse(
    status=result.status,
    trace_count=len(result.traces),
    span_count=sum(len(trace["spans"]) for trace in result.traces),
    evidence=_evidence_response(evidence),
  )
