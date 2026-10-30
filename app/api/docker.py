import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.exceptions import (
  DockerIntegrationError,
  IncidentNotFoundError,
  PermissionDeniedError,
  ProjectNotFoundError,
  SourceConfigurationError,
  SourceNotFoundError,
)
from app.db.database import get_db
from app.db.user import User
from app.schemas.docker_schema import (
  DockerConnectionResponse,
  DockerContainerListResponse,
  DockerInvestigationRequest,
  DockerInvestigationResponse,
)
from app.services.docker_service import (
  collect_docker_investigation,
  list_docker_containers,
  persist_docker_investigation,
  validate_docker_connection,
)
from app.services.incident_service import get_project_incident
from app.services.source_service import get_project_docker_source

router = APIRouter(tags=["docker investigation"])


def _raise_access_error(error: Exception) -> HTTPException:
  if isinstance(error, (ProjectNotFoundError, IncidentNotFoundError)):
    return HTTPException(status_code=404, detail=str(error))
  if isinstance(error, PermissionDeniedError):
    return HTTPException(status_code=403, detail=str(error))
  raise error


@router.post(
  "/projects/{project_id}/sources/{source_id}/docker/validate",
  response_model=DockerConnectionResponse,
)
async def validate_docker_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> DockerConnectionResponse:
  try:
    await get_project_docker_source(session, project_id, source_id, user)
    await session.rollback()
    result = await validate_docker_connection()
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except DockerIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return DockerConnectionResponse(**result)


@router.get(
  "/projects/{project_id}/sources/{source_id}/docker/containers",
  response_model=DockerContainerListResponse,
)
async def list_docker_source_containers(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> DockerContainerListResponse:
  try:
    await get_project_docker_source(session, project_id, source_id, user)
    await session.rollback()
    result = await list_docker_containers()
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except DockerIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return DockerContainerListResponse(**result)


@router.post(
  "/projects/{project_id}/docker/investigations",
  response_model=DockerInvestigationResponse,
)
async def investigate_docker_container(
  project_id: uuid.UUID,
  request: DockerInvestigationRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> DockerInvestigationResponse:
  try:
    source = await get_project_docker_source(
      session,
      project_id,
      request.source_id,
      user,
    )
    incident = (
      await get_project_incident(
        session,
        project_id,
        request.incident_id,
        user,
      )
      if request.incident_id is not None
      else None
    )
  except (
    ProjectNotFoundError,
    IncidentNotFoundError,
    PermissionDeniedError,
  ) as error:
    raise _raise_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error

  source_id = source.id
  source_project_id = source.project_id
  incident_id = incident.id if incident is not None else None
  await session.rollback()
  investigation = await collect_docker_investigation(
    source_id,
    source_project_id,
    request.container_id,
    request.log_tail_lines,
  )
  evidence_id = None
  if incident_id is not None:
    try:
      evidence = await persist_docker_investigation(
        session,
        project_id,
        incident_id,
        source_id,
        investigation,
        request.log_tail_lines,
      )
    except SourceConfigurationError as error:
      raise HTTPException(status_code=409, detail=str(error)) from error
    evidence_id = evidence.id
  return DockerInvestigationResponse(
    **investigation,
    incident_evidence_id=evidence_id,
  )
