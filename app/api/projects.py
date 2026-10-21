import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.exceptions import (
  PermissionDeniedError,
  ProjectConflictError,
  ProjectNotFoundError,
)
from app.db.database import get_db
from app.db.project import Project
from app.db.user import User
from app.schemas.project_schema import (
  ProjectCreateRequest,
  ProjectResponse,
  ProjectUpdateRequest,
)
from app.services.project_service import (
  create_project,
  delete_project,
  get_accessible_project,
  list_accessible_projects,
  update_project,
)

router = APIRouter(prefix="/projects", tags=["projects"])


def _project_response(project: Project, role: str) -> ProjectResponse:
  return ProjectResponse(
    id=project.id,
    name=project.name,
    description=project.description,
    role=role,
  )


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create(
  request: ProjectCreateRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> ProjectResponse:
  try:
    project = await create_project(session, user, request)
  except ProjectConflictError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  return _project_response(project, "owner")


@router.get("", response_model=list[ProjectResponse])
async def list_mine(
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[ProjectResponse]:
  projects = await list_accessible_projects(session, user)
  return [
    _project_response(project, role)
    for project, role in projects
  ]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_one(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> ProjectResponse:
  try:
    project, role = await get_accessible_project(session, project_id, user)
  except ProjectNotFoundError as error:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail=str(error),
    ) from error
  return _project_response(project, role)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update(
  project_id: uuid.UUID,
  request: ProjectUpdateRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> ProjectResponse:
  try:
    project, role = await update_project(
      session,
      project_id,
      user,
      request,
    )
  except ProjectNotFoundError as error:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail=str(error),
    ) from error
  except PermissionDeniedError as error:
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail=str(error),
    ) from error
  except ProjectConflictError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  return _project_response(project, role)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> Response:
  try:
    await delete_project(session, project_id, user)
  except ProjectNotFoundError as error:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail=str(error),
    ) from error
  except PermissionDeniedError as error:
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail=str(error),
    ) from error
  except ProjectConflictError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  return Response(status_code=status.HTTP_204_NO_CONTENT)
