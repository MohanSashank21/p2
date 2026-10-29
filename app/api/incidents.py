import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_user
from app.core.exceptions import (
  IncidentNotFoundError,
  InvalidIncidentTransitionError,
  LokiIntegrationError,
  PermissionDeniedError,
  ProjectNotFoundError,
  RateLimitExceededError,
  SourceConfigurationError,
  SourceNotFoundError,
)
from app.db.database import get_db
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource
from app.db.redis import get_redis
from app.db.user import User
from app.schemas.incident_schema import (
  IncidentCreateRequest,
  IncidentEvidenceResponse,
  IncidentResponse,
  IncidentStatusUpdateRequest,
  LokiQueryResponse,
)
from app.schemas.source_schema import LokiQueryRequest
from app.services.incident_service import (
  create_manual_incident,
  get_incident_log_labels,
  get_project_incident,
  list_incident_evidence,
  list_project_incidents,
  update_incident_status,
)
from app.services.loki_service import (
  LokiConnection,
  persist_loki_evidence,
  query_loki,
)
from app.services.redis_service import rate_limit_loki_queries
from app.services.source_service import get_project_loki_source

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
