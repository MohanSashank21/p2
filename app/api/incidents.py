import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.exceptions import (
  IncidentNotFoundError,
  InvalidIncidentTransitionError,
  PermissionDeniedError,
  ProjectNotFoundError,
)
from app.db.database import get_db
from app.db.incident import Incident, IncidentEvidence
from app.db.user import User
from app.schemas.incident_schema import (
  IncidentCreateRequest,
  IncidentEvidenceResponse,
  IncidentResponse,
  IncidentStatusUpdateRequest,
)
from app.services.incident_service import (
  create_manual_incident,
  get_project_incident,
  list_incident_evidence,
  list_project_incidents,
  update_incident_status,
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
