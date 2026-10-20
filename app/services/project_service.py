import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  EmailDeliveryError,
  PermissionDeniedError,
  ProjectConflictError,
  ProjectNotFoundError,
  ProjectTargetError,
)
from app.db.membership import Membership
from app.db.project import Project
from app.db.project_invitation import ProjectInvitation
from app.db.project_membership import ProjectMembership
from app.db.user import User
from app.schemas.project_schema import ProjectCreateRequest
from app.services.email_service import send_email
from app.services.redis_service import bump_rate_limit

PROJECT_INVITATION_EXPIRE_DAYS = 7


def hash_project_invitation_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()

async def rate_limit_project_invitation(
  redis: Redis,
  inviter: User,
  client_ip: str,
) -> None:
  await bump_rate_limit(
    redis,
    "project-invite:actor",
    str(inviter.id),
    limit=20,
    window_seconds=3600,
  )
  if client_ip:
    await bump_rate_limit(
      redis,
      "project-invite:ip",
      client_ip,
      limit=50,
      window_seconds=3600,
    )

async def verified_organisation_invitee(
  session: AsyncSession,
  organisation_id: uuid.UUID,
  user_id: uuid.UUID,
) -> User:
  user = await session.scalar(
    select(User)
    .join(Membership, Membership.user_id == User.id)
    .where(
      Membership.organisation_id == organisation_id,
      User.id == user_id,
      User.email_verified.is_(True),
    ),
  )
  if user is None:
    raise ProjectTargetError(
      "Project invitations can only be sent to verified members of this organization",
    )
  return user

async def _ensure_no_pending_invitation(
  session: AsyncSession,
  organisation_id: uuid.UUID,
  invitee: User,
  role: str,
  project_id: uuid.UUID | None,
  project_name: str | None,
) -> None:
  conditions = [
    ProjectInvitation.organisation_id == organisation_id,
    ProjectInvitation.invitee_user_id == invitee.id,
    ProjectInvitation.role == role,
    ProjectInvitation.accepted_at.is_(None),
    ProjectInvitation.expires_at > datetime.now(timezone.utc),
  ]
  if role == "manager":
    conditions.append(ProjectInvitation.proposed_project_name == project_name)
  else:
    conditions.append(ProjectInvitation.project_id == project_id)
  pending = await session.scalar(
    select(ProjectInvitation.id).where(*conditions),
  )
  if pending is not None:
    raise ProjectConflictError(
      "A project invitation is already pending for this user and project",
    )

async def _send_project_invitation(
  session: AsyncSession,
  invitation: ProjectInvitation,
  recipient_email: str,
  subject: str,
  message: str,
) -> ProjectInvitation:
  raw_token = secrets.token_urlsafe(48)
  invitation.token_hash = hash_project_invitation_token(raw_token)
  invitation.expires_at = datetime.now(timezone.utc) + timedelta(
    days=PROJECT_INVITATION_EXPIRE_DAYS,
  )
  session.add(invitation)
  await session.commit()

  accept_url = (
    f"{settings.FRONTEND_BASE_URL.rstrip('/')}/accept-project-invitation?"
    f"{urlencode({'token': raw_token})}"
  )
  try:
    await send_email(
      recipient_email,
      subject,
      (
        f"{message}\n\n"
        f"Sign in to OpsPilot with this email and accept the invitation here:\n"
        f"{accept_url}\n\n"
        f"This invitation expires in {PROJECT_INVITATION_EXPIRE_DAYS} days."
      ),
    )
  except EmailDeliveryError:
    invitation.expires_at = datetime.now(timezone.utc)
    await session.commit()
    raise
  return invitation


async def create_project_manager_invitation(
  redis: Redis,
  session: AsyncSession,
  organisation_id: uuid.UUID,
  owner: User,
  request: ProjectCreateRequest,
  client_ip: str,
) -> ProjectInvitation:
  await rate_limit_project_invitation(redis, owner, client_ip)
  manager = await verified_organisation_invitee(
    session,
    organisation_id,
    request.manager_user_id,
  )
  existing_project = await session.scalar(
    select(Project.id).where(
      Project.organisation_id == organisation_id,
      Project.name == request.name,
    ),
  )
  if existing_project is not None:
    raise ProjectConflictError(
      "A project with this name already exists in the organization",
    )

  pending_project = await session.scalar(
    select(ProjectInvitation.id).where(
      ProjectInvitation.organisation_id == organisation_id,
      ProjectInvitation.role == "manager",
      ProjectInvitation.proposed_project_name == request.name,
      ProjectInvitation.accepted_at.is_(None),
      ProjectInvitation.expires_at > datetime.now(timezone.utc),
    ),
  )
  if pending_project is not None:
    raise ProjectConflictError(
      "A manager invitation for this project is already pending",
    )

  await _ensure_no_pending_invitation(
    session,
    organisation_id,
    manager,
    "manager",
    None,
    request.name,
  )

  invitation = ProjectInvitation(
    organisation_id=organisation_id,
    project_id=None,
    accepted_project_id=None,
    invited_by_user_id=owner.id,
    invitee_user_id=manager.id,
    role="manager",
    proposed_project_name=request.name,
    proposed_project_description=request.description,
    token_hash="pending",
    expires_at=datetime.now(timezone.utc),
  )
  return await _send_project_invitation(
    session,
    invitation,
    manager.email,
    f"Project manager invitation: {request.name}",
    (
      f"You have been invited to manage the proposed project "
      f"\"{request.name}\" in your organization."
    ),
  )

async def invite_project_worker(
  redis: Redis,
  session: AsyncSession,
  organisation_id: uuid.UUID,
  project_id: uuid.UUID,
  inviter: User,
  inviter_organisation_role: str,
  invitee_user_id: uuid.UUID,
  client_ip: str,
) -> ProjectInvitation:
  await rate_limit_project_invitation(redis, inviter, client_ip)
  project = await session.scalar(
    select(Project).where(
      Project.id == project_id,
      Project.organisation_id == organisation_id,
    ),
  )
  if project is None:
    raise ProjectNotFoundError("Project not found")

  if inviter_organisation_role != "owner":
    inviter_project_role = await session.scalar(
      select(ProjectMembership.role).where(
        ProjectMembership.project_id == project_id,
        ProjectMembership.user_id == inviter.id,
      ),
    )
    if inviter_project_role != "manager":
      raise PermissionDeniedError(
        "Only the organization owner or this project's manager can invite workers",
      )

  invitee = await verified_organisation_invitee(
    session,
    organisation_id,
    invitee_user_id,
  )
  if invitee.id == inviter.id and inviter_organisation_role != "owner":
    raise ProjectTargetError("You cannot invite yourself to this project")

  existing_membership = await session.scalar(
    select(ProjectMembership.id).where(
      ProjectMembership.project_id == project_id,
      ProjectMembership.user_id == invitee.id,
    ),
  )
  if existing_membership is not None:
    raise ProjectConflictError("This user is already assigned to the project")

  await _ensure_no_pending_invitation(
    session,
    organisation_id,
    invitee,
    "worker",
    project_id,
    None,
  )

  invitation = ProjectInvitation(
    organisation_id=organisation_id,
    project_id=project_id,
    accepted_project_id=None,
    invited_by_user_id=inviter.id,
    invitee_user_id=invitee.id,
    role="worker",
    proposed_project_name=None,
    proposed_project_description=None,
    token_hash="pending",
    expires_at=datetime.now(timezone.utc),
  )
  return await _send_project_invitation(
    session,
    invitation,
    invitee.email,
    f"Invitation to join {project.name}",
    f"You have been invited to join the project \"{project.name}\" as a worker.",
  )

async def list_accessible_projects(
  session: AsyncSession,
  organisation_id: uuid.UUID,
  user: User,
  organisation_role: str,
) -> list[tuple[Project, str]]:
  if organisation_role == "owner":
    result = await session.execute(
      select(Project, ProjectMembership.role)
      .outerjoin(
        ProjectMembership,
        (ProjectMembership.project_id == Project.id)
        & (ProjectMembership.user_id == user.id),
      )
      .where(Project.organisation_id == organisation_id)
      .order_by(Project.name, Project.id),
    )
    return [
      (project, project_role or "owner")
      for project, project_role in result
    ]

  result = await session.execute(
    select(Project, ProjectMembership.role)
    .join(
      ProjectMembership,
      ProjectMembership.project_id == Project.id,
    )
    .where(
      Project.organisation_id == organisation_id,
      ProjectMembership.user_id == user.id,
    )
    .order_by(Project.name, Project.id),
  )
  return list(result)


async def accept_project_invitation(
  session: AsyncSession,
  user: User,
  raw_token: str,
) -> tuple[Project, str]:
  invitation = await session.scalar(
    select(ProjectInvitation)
    .where(
      ProjectInvitation.token_hash
      == hash_project_invitation_token(raw_token),
    )
    .with_for_update(),
  )
  now = datetime.now(timezone.utc)
  expires_at = invitation.expires_at if invitation is not None else None
  if expires_at is not None and expires_at.tzinfo is None:
    expires_at = expires_at.replace(tzinfo=timezone.utc)
  if (
    invitation is None
    or invitation.accepted_at is not None
    or expires_at is None
    or expires_at <= now
    or invitation.invitee_user_id != user.id
    or not user.email_verified
  ):
    raise PermissionDeniedError("Project invitation is invalid or expired")

  organisation_membership = await session.scalar(
    select(Membership.id).where(
      Membership.organisation_id == invitation.organisation_id,
      Membership.user_id == user.id,
    ),
  )
  if organisation_membership is None:
    raise PermissionDeniedError(
      "You must belong to the organization to accept this project invitation",
    )

  if invitation.role == "manager":
    if invitation.proposed_project_name is None:
      raise PermissionDeniedError("Project invitation is invalid or expired")
    project = Project(
      organisation_id=invitation.organisation_id,
      name=invitation.proposed_project_name,
      description=invitation.proposed_project_description,
    )
  else:
    project = await session.scalar(
      select(Project).where(
        Project.id == invitation.project_id,
        Project.organisation_id == invitation.organisation_id,
      ),
    )
    if project is None:
      raise PermissionDeniedError(
        "The project for this invitation no longer exists",
      )

  existing_membership = None
  if invitation.role == "worker":
    existing_membership = await session.scalar(
      select(ProjectMembership.id).where(
        ProjectMembership.project_id == project.id,
        ProjectMembership.user_id == user.id,
      ),
    )
  if existing_membership is not None:
    raise ProjectConflictError("You are already assigned to this project")

  try:
    session.add(project)
    await session.flush()
    project_membership = ProjectMembership(
      project_id=project.id,
      organisation_id=invitation.organisation_id,
      user_id=user.id,
      role=invitation.role,
    )
    session.add(project_membership)
    invitation.accepted_at = now
    invitation.accepted_project_id = project.id
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise ProjectConflictError(
      "The project or project membership conflicts with existing data",
    ) from error
  return project, invitation.role
