import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_organisation_role
from app.core.exceptions import (
  EmailDeliveryError,
  InvitationTargetError,
  OrganisationConflictError,
  PermissionDeniedError,
  RateLimitExceededError,
)
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.schemas.auth_schema import (
  OrganisationInvitationAcceptRequest,
  OrganisationInvitationRequest,
  OrganisationInvitationResponse,
)
from app.schemas.organisation_schema import (
  OrganisationCreateRequest,
  OrganisationResponse,
)
from app.services.organisation_service import (
  accept_organisation_invitation,
  create_organisation,
  create_organisation_invitation,
  list_user_organisations,
  INVITATION_EXPIRE_DAYS,
)

router = APIRouter(prefix="/organisations", tags=["organisations"])

@router.post(
  "",
  response_model=OrganisationResponse,
  status_code=status.HTTP_201_CREATED,
)

async def create(
  request: OrganisationCreateRequest,
  current_user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> OrganisationResponse:
  try:
    organisation = await create_organisation(
      session,
      current_user,
      request.name,
    )
  except OrganisationConflictError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  return OrganisationResponse(
    id=organisation.id,
    name=organisation.name,
    owner_user_id=organisation.owner_user_id,
    role="owner",
  )

@router.get("", response_model=list[OrganisationResponse])
async def list_mine(
  current_user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[OrganisationResponse]:
  memberships = await list_user_organisations(session, current_user)
  return [
    OrganisationResponse(
      id=organisation.id,
      name=organisation.name,
      owner_user_id=organisation.owner_user_id,
      role=membership.role,
    )
    for organisation, membership in memberships
  ]

@router.post(
  "/{organisation_id}/invitations",
  response_model=OrganisationInvitationResponse,
  status_code=status.HTTP_202_ACCEPTED,
)

async def invite_to_organisation(
  organisation_id: uuid.UUID,
  request: OrganisationInvitationRequest,
  http_request: Request,
  inviter: User = Depends(get_current_user),
  membership: Membership = Depends(
    require_organisation_role("owner"),
  ),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> OrganisationInvitationResponse:
  try:
    await create_organisation_invitation(
      redis,
      session,
      inviter,
      organisation_id,
      request,
      http_request.client.host if http_request.client else "",
    )
  except PermissionDeniedError as error:
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail=str(error),
    ) from error
  except InvitationTargetError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
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
      detail="Invitation email could not be delivered",
    ) from error
  return OrganisationInvitationResponse(
    message="Invitation email sent.",
    expires_in=INVITATION_EXPIRE_DAYS * 24 * 60 * 60,
  )


@router.post("/invitations/accept", status_code=status.HTTP_200_OK)
async def accept_invitation(
  request: OrganisationInvitationAcceptRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> dict[str, str | uuid.UUID]:
  try:
    membership = await accept_organisation_invitation(
      session,
      user,
      request.token,
    )
  except PermissionDeniedError as error:
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail=str(error),
    ) from error

  organisation = await session.scalar(
    select(Organisation).where(
      Organisation.id == membership.organisation_id,
    ),
  )
  return {
    "organisation_id": membership.organisation_id,
    "organisation_name": organisation.name if organisation else "",
    "role": membership.role,
  }
