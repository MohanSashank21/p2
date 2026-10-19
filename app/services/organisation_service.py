import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  BootstrapUnavailableError,
  EmailDeliveryError,
  InvitationTargetError,
  PermissionDeniedError,
)
from app.db.auth import OrganisationInvitation, PlatformBootstrap
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.schemas.auth_schema import OrganisationInvitationRequest
from app.services.auth_service import _utc
from app.services.email_service import send_email
from app.services.redis_service import bump_rate_limit

INVITATION_EXPIRE_DAYS = 7


def _hash_invitation_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def bootstrap_organisation(
  session: AsyncSession,
  user: User,
  name: str,
) -> Organisation:
  state = await session.scalar(
    select(PlatformBootstrap)
    .where(PlatformBootstrap.key == "platform")
    .with_for_update()
  )
  if state is None or state.completed_at is not None:
    raise BootstrapUnavailableError("Platform bootstrap is unavailable")

  organisation = Organisation(name=name)
  session.add(organisation)
  await session.flush()
  session.add(
    Membership(
      organisation_id=organisation.id,
      user_id=user.id,
      role="owner",
    ),
  )
  state.completed_at = datetime.now(timezone.utc)
  await session.commit()
  return organisation


async def create_organisation_invitation(
  redis: Redis,
  session: AsyncSession,
  inviter: User,
  organisation_id: uuid.UUID,
  request: OrganisationInvitationRequest,
  client_ip: str,
  inviter_role: str,
) -> OrganisationInvitation | None:
  email = str(request.email).strip().casefold()
  if inviter_role == "admin" and request.role != "worker":
    raise PermissionDeniedError("Admins may invite workers only")
  await bump_rate_limit(
    redis,
    "invite:actor",
    str(inviter.id),
    limit=20,
    window_seconds=int(timedelta(hours=1).total_seconds()),
  )
  if client_ip:
    await bump_rate_limit(
      redis,
      "invite:ip",
      client_ip,
      limit=50,
      window_seconds=int(timedelta(hours=1).total_seconds()),
    )

  invited_user = await session.scalar(
    select(User).where(
      User.email == email,
      User.email_verified.is_(True),
    ),
  )
  if invited_user is None:
    raise InvitationTargetError(
      "Invitations can only be sent to an existing verified account",
    )

  organization = await session.get(Organisation, organisation_id)
  if organization is None:
    return None
  existing_membership = await session.scalar(
    select(Membership)
    .join(User, Membership.user_id == User.id)
    .where(
      Membership.organisation_id == organisation_id,
      User.email == email,
    ),
  )
  if existing_membership is not None:
    raise InvitationTargetError(
      "This user is already a member of the organisation",
    )

  pending_invitation = await session.scalar(
    select(OrganisationInvitation).where(
      OrganisationInvitation.organisation_id == organisation_id,
      OrganisationInvitation.email == email,
      OrganisationInvitation.accepted_at.is_(None),
      OrganisationInvitation.expires_at > datetime.now(timezone.utc),
    ),
  )
  if pending_invitation is not None:
    raise InvitationTargetError(
      "An invitation is already pending for this user",
    )

  raw_token = secrets.token_urlsafe(48)
  invitation = OrganisationInvitation(
    organisation_id=organisation_id,
    invited_by_user_id=inviter.id,
    email=email,
    role=request.role,
    token_hash=_hash_invitation_token(raw_token),
    expires_at=datetime.now(timezone.utc)
    + timedelta(days=INVITATION_EXPIRE_DAYS),
  )
  session.add(invitation)
  await session.commit()

  accept_url = (
    f"{settings.FRONTEND_BASE_URL.rstrip('/')}/accept-invitation?"
    f"{urlencode({'token': raw_token})}"
  )
  try:
    await send_email(
      email,
      f"Invitation to {organization.name}",
      (
        f"You have been invited to join {organization.name} as a "
        f"{request.role}.\n\n"
        f"Sign in or create a verified account with this email, then accept "
        f"the invitation here:\n{accept_url}\n\n"
        f"This invitation expires in {INVITATION_EXPIRE_DAYS} days."
      ),
    )
  except EmailDeliveryError:
    invitation.expires_at = datetime.now(timezone.utc)
    await session.commit()
    raise
  return invitation


async def accept_organisation_invitation(
  session: AsyncSession,
  user: User,
  raw_token: str,
) -> Membership:
  invitation = await session.scalar(
    select(OrganisationInvitation)
    .where(
      OrganisationInvitation.token_hash == _hash_invitation_token(raw_token),
    )
    .with_for_update()
  )
  if (
    invitation is None
    or invitation.accepted_at is not None
    or _utc(invitation.expires_at) <= datetime.now(timezone.utc)
    or invitation.email != user.email
    or not user.email_verified
  ):
    raise PermissionDeniedError("Invitation is invalid or expired")

  membership = await session.scalar(
    select(Membership).where(
      Membership.organisation_id == invitation.organisation_id,
      Membership.user_id == user.id,
    ),
  )
  if membership is None:
    membership = Membership(
      organisation_id=invitation.organisation_id,
      user_id=user.id,
      role=invitation.role,
    )
    session.add(membership)
  invitation.accepted_at = datetime.now(timezone.utc)
  await session.commit()
  return membership
