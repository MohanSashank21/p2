import hashlib
import uuid
from datetime import datetime, timezone
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  InvitationTargetError,
  OrganisationConflictError,
  PermissionDeniedError,
)

from app.db.auth import OrganisationInvitation
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.schemas.auth_schema import OrganisationInvitationRequest
from app.services.auth_service import _utc
from app.services.email_service import send_email
from app.services.invitation_service import lock_invitation_target
from app.services.outbox_service import enqueue_invitation_email
from app.services.redis_service import rate_limit_invitation

INVITATION_EXPIRE_DAYS = 7

async def create_organisation(
  session: AsyncSession,
  user: User,
  name: str,
) -> Organisation:
  normalized_name = name.strip()
  existing_organisation = await session.scalar(
    select(Organisation.id).where(
      func.lower(func.btrim(Organisation.name)) == normalized_name.lower(),
    ),
  )
  if existing_organisation is not None:
    raise OrganisationConflictError(
      "An organisation with this name already exists",
    )

  organisation = Organisation(
    name=normalized_name,
    owner_user_id=user.id,
  )
  session.add(organisation)
  committed = False
  try:
    await session.flush()
    session.add(
      Membership(
        organisation_id=organisation.id,
        user_id=user.id,
        role="owner",
      ),
    )
    await session.flush()
    await session.commit()
    committed = True
    return organisation
  except IntegrityError as error:
    constraint_name = getattr(
      getattr(error.orig, "diag", None),
      "constraint_name",
      None,
    )
    if (
      constraint_name == "uq_organisations_name_normalized"
      or "uq_organisations_name_normalized" in str(error.orig)
    ):
      raise OrganisationConflictError(
        "An organisation with this name already exists",
      ) from error
    raise
  finally:
    if not committed:
      await session.rollback()

async def list_user_organisations(
  session: AsyncSession,
  user: User,
) -> list[tuple[Organisation, Membership]]:
  result = await session.execute(
    select(Organisation, Membership)
    .join(Membership, Membership.organisation_id == Organisation.id)
    .where(Membership.user_id == user.id)
    .order_by(Organisation.name, Organisation.id),
  )
  return list(result)

def _hash_invitation_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()

async def create_organisation_invitation(
  redis: Redis,
  session: AsyncSession,
  inviter: User,
  organisation_id: uuid.UUID,
  request: OrganisationInvitationRequest,
  client_ip: str,
) -> OrganisationInvitation | None:
  email = str(request.email).strip().lower()
  await rate_limit_invitation(
    redis,
    "organisation-invite",
    str(inviter.id),
    email,
    client_ip,
  )

  organization = await session.get(Organisation, organisation_id)
  if organization is None:
    return None
  await lock_invitation_target(
    session,
    "organisation",
    f"{organisation_id}:{email.lower()}",
  )
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
      func.lower(OrganisationInvitation.email) == email.lower(),
      OrganisationInvitation.accepted_at.is_(None),
    ).with_for_update(),
  )

  if pending_invitation is None:
    invitation = OrganisationInvitation(
      organisation_id=organisation_id,
      invited_by_user_id=inviter.id,
      email=email,
      role=request.role,
      token_hash="pending",
      expires_at=datetime.now(timezone.utc),
    )
    session.add(invitation)
  else:
    invitation = pending_invitation
    invitation.invited_by_user_id = inviter.id
    invitation.role = request.role
  await enqueue_invitation_email(
    session,
    invitation,
    invitation_type="organisation",
    recipient=email,
    subject=f"Invitation to {organization.name}",
    message=(
      f"You have been invited to join {organization.name} as a "
      f"{request.role}."
    ),
    accept_path="/accept-invitation",
    target_scope="organisation",
    target_key=f"{organisation_id}:{email.lower()}",
    expiry_days=INVITATION_EXPIRE_DAYS,
    sender=send_email,
  )
  return invitation

async def accept_organisation_invitation(
  session: AsyncSession,
  user: User,
  raw_token: str,
) -> Membership:
  candidate = await session.scalar(
    select(OrganisationInvitation)
    .where(
      OrganisationInvitation.token_hash == _hash_invitation_token(raw_token),
    ),
  )
  if candidate is None:
    raise PermissionDeniedError("Invitation is invalid or expired")
  await lock_invitation_target(
    session,
    "organisation",
    f"{candidate.organisation_id}:{candidate.email.lower()}",
  )
  invitation = await session.scalar(
    select(OrganisationInvitation)
    .where(OrganisationInvitation.id == candidate.id)
    .with_for_update()
    .execution_options(populate_existing=True),
  )
  if (
    invitation is None
    or invitation.token_hash != _hash_invitation_token(raw_token)
    or invitation.accepted_at is not None
    or _utc(invitation.expires_at) <= datetime.now(timezone.utc)
    or invitation.email.casefold() != user.email.casefold()
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
