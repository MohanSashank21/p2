import hmac
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_organisation_role
from app.core.config import settings
from app.core.exceptions import (
  BootstrapUnavailableError,
  EmailDeliveryError,
  InvitationTargetError,
  PermissionDeniedError,
  RateLimitExceededError,
)
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.schemas.auth_schema import (
  OrganisationBootstrapRequest,
  OrganisationBootstrapResponse,
  OrganisationInvitationAcceptRequest,
  OrganisationInvitationRequest,
  OrganisationInvitationResponse,
)
from app.services.organisation_service import (
  accept_organisation_invitation,
  bootstrap_organisation,
  create_organisation_invitation,
  INVITATION_EXPIRE_DAYS,
)

router = APIRouter(prefix="/organisations", tags=["organisations"])


@router.post(
  "/bootstrap",
  response_model=OrganisationBootstrapResponse,
  status_code=status.HTTP_201_CREATED,
)
async def bootstrap(
  request: OrganisationBootstrapRequest,
  current_user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
  bootstrap_token: Annotated[str | None, Header(alias="X-Platform-Bootstrap-Token")] = None,
) -> OrganisationBootstrapResponse:
  configured_token = settings.PLATFORM_BOOTSTRAP_TOKEN
  if (
    configured_token is None
    or len(configured_token.get_secret_value().encode("utf-8")) < 32
  ):
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="Platform bootstrap is not configured",
    )
  expected_token = configured_token.get_secret_value()
  if not hmac.compare_digest(bootstrap_token or "", expected_token):
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail="Invalid platform bootstrap token",
    )
  try:
    organisation = await bootstrap_organisation(
      session,
      current_user,
      request.name,
    )
  except BootstrapUnavailableError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail=str(error),
    ) from error
  return OrganisationBootstrapResponse(
    organisation_id=organisation.id,
    name=organisation.name,
  )


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
    require_organisation_role("owner", "admin"),
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
      membership.role,
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
