import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_organisation_role
from app.core.exceptions import (
  EmailDeliveryError,
  PermissionDeniedError,
  ProjectConflictError,
  ProjectNotFoundError,
  ProjectTargetError,
  RateLimitExceededError,
)
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.membership import Membership
from app.db.user import User
from app.schemas.project_schema import (
  ProjectInvitationAcceptRequest,
  ProjectInvitationResponse,
  ProjectCreateRequest,
  ProjectWorkerInvitationRequest,
  ProjectResponse,
)
from app.services.project_service import (
  PROJECT_INVITATION_EXPIRE_DAYS,
  accept_project_invitation,
  create_project_manager_invitation,
  invite_project_worker,
  list_accessible_projects,
)

router = APIRouter(tags=["projects"])


@router.post(
  "/organisations/{organisation_id}/projects",
  response_model=ProjectInvitationResponse,
  status_code=status.HTTP_202_ACCEPTED,
)
async def invite_project_manager(
  organisation_id: uuid.UUID,
  request: ProjectCreateRequest,
  http_request: Request,
  owner: User = Depends(get_current_user),
  membership: Membership = Depends(
    require_organisation_role("owner"),
  ),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> ProjectInvitationResponse:
  try:
    await create_project_manager_invitation(
      redis,
      session,
      organisation_id,
      owner,
      request,
      http_request.client.host if http_request.client else "",
    )
  except ProjectTargetError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  except ProjectConflictError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=status.HTTP_429_TOO_MANY_REQUESTS,
      detail=str(error),
      headers={"Retry-After": "3600"},
    ) from error
  except EmailDeliveryError as error:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="Project manager invitation email could not be delivered",
    ) from error
  return ProjectInvitationResponse(
    message="Project proposal invitation sent.",
    expires_in=PROJECT_INVITATION_EXPIRE_DAYS * 24 * 60 * 60,
  )


@router.get(
  "/organisations/{organisation_id}/projects",
  response_model=list[ProjectResponse],
)
async def list_organisation_projects(
  organisation_id: uuid.UUID,
  current_user: User = Depends(get_current_user),
  membership: Membership = Depends(
    require_organisation_role("owner", "member"),
  ),
  session: AsyncSession = Depends(get_db),
) -> list[ProjectResponse]:
  projects = await list_accessible_projects(
    session,
    organisation_id,
    current_user,
    membership.role,
  )
  return [
    ProjectResponse(
      id=project.id,
      organisation_id=project.organisation_id,
      name=project.name,
      description=project.description,
      role=role,
    )
    for project, role in projects
  ]


@router.post(
  "/organisations/{organisation_id}/projects/{project_id}/worker-invitations",
  response_model=ProjectInvitationResponse,
  status_code=status.HTTP_202_ACCEPTED,
)
async def invite_project_worker_endpoint(
  organisation_id: uuid.UUID,
  project_id: uuid.UUID,
  request: ProjectWorkerInvitationRequest,
  http_request: Request,
  current_user: User = Depends(get_current_user),
  organisation_membership: Membership = Depends(
    require_organisation_role("owner", "member"),
  ),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> ProjectInvitationResponse:
  try:
    await invite_project_worker(
      redis,
      session,
      organisation_id,
      project_id,
      current_user,
      organisation_membership.role,
      request.user_id,
      http_request.client.host if http_request.client else "",
    )
  except ProjectNotFoundError as error:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail=str(error),
    ) from error
  except ProjectTargetError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
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
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=status.HTTP_429_TOO_MANY_REQUESTS,
      detail=str(error),
      headers={"Retry-After": "3600"},
    ) from error
  except EmailDeliveryError as error:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="Project worker invitation email could not be delivered",
    ) from error
  return ProjectInvitationResponse(
    message="Project worker invitation sent.",
    expires_in=PROJECT_INVITATION_EXPIRE_DAYS * 24 * 60 * 60,
  )


@router.post(
  "/project-invitations/accept",
  response_model=ProjectResponse,
)
async def accept_project_invitation_endpoint(
  request: ProjectInvitationAcceptRequest,
  current_user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> ProjectResponse:
  try:
    project, role = await accept_project_invitation(
      session,
      current_user,
      request.token,
    )
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
  return ProjectResponse(
    id=project.id,
    organisation_id=project.organisation_id,
    name=project.name,
    description=project.description,
    role=role,
  )
