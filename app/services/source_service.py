import hashlib
import hmac
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  PermissionDeniedError,
  ProjectNotFoundError,
  SourceConflictError,
  SourceCredentialError,
  SourceNotFoundError,
)
from app.db.environment import Environment
from app.db.incident import Incident
from app.db.incident_source import IncidentSource, SourceEvent
from app.db.user import User
from app.schemas.source_schema import IncomingSourceEvent, SourceCreateRequest
from app.services.project_service import get_accessible_project
from app.services.incident_service import create_webhook_incident


def _credential_hash(credential: str) -> str:
  return hashlib.sha256(credential.encode("utf-8")).hexdigest()


async def create_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  request: SourceCreateRequest,
) -> tuple[IncidentSource, str]:
  _project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can manage event sources")

  if request.environment_id is not None:
    environment = await session.scalar(
      select(Environment.id).where(
        Environment.id == request.environment_id,
        Environment.project_id == project_id,
      ),
    )
    if environment is None:
      raise ProjectNotFoundError("Environment not found in this project")

  credential = secrets.token_urlsafe(32)
  source = IncidentSource(
    project_id=project_id,
    environment_id=request.environment_id,
    name=request.name,
    source_type=request.source_type,
    credential_hash=_credential_hash(credential),
    enabled=True,
  )
  session.add(source)
  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise SourceConflictError(
      "A source with this name already exists in the project",
    ) from error
  await session.refresh(source)
  return source, credential


async def list_sources(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> list[IncidentSource]:
  await get_accessible_project(session, project_id, user)
  result = await session.scalars(
    select(IncidentSource)
    .where(IncidentSource.project_id == project_id)
    .order_by(IncidentSource.name, IncidentSource.id),
  )
  return list(result)


async def _get_managed_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  _project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can manage event sources")
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
    ),
  )
  if source is None:
    raise SourceNotFoundError("Source not found")
  return source


async def rotate_source_credential(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> tuple[IncidentSource, str]:
  source = await _get_managed_source(session, project_id, source_id, user)
  credential = secrets.token_urlsafe(32)
  source.credential_hash = _credential_hash(credential)
  await session.commit()
  await session.refresh(source)
  return source, credential


async def disable_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  source.enabled = False
  await session.commit()
  await session.refresh(source)
  return source


async def authenticate_source(
  session: AsyncSession,
  source_id: uuid.UUID,
  credential: str | None,
) -> IncidentSource:
  source = await session.get(IncidentSource, source_id)
  if (
    source is None
    or not source.enabled
    or credential is None
    or not hmac.compare_digest(
      source.credential_hash,
      _credential_hash(credential),
    )
  ):
    raise SourceCredentialError("Invalid or disabled source credential")
  return source


async def receive_source_event(
  session: AsyncSession,
  source: IncidentSource,
  request: IncomingSourceEvent,
  original_payload: dict,
) -> tuple[SourceEvent, Incident, bool]:
  source_id = source.id
  project_id = source.project_id
  environment_id = source.environment_id
  event = SourceEvent(
    source_id=source_id,
    project_id=project_id,
    environment_id=environment_id,
    external_event_id=request.event_id,
    event_type=request.event_type,
    title=request.title,
    description=request.description,
    severity=request.severity,
    original_payload=original_payload,
  )
  session.add(event)
  try:
    await session.flush()
    incident = await create_webhook_incident(
      session,
      project_id=project_id,
      environment_id=environment_id,
      source_event_id=event.id,
      incident_type=request.event_type,
      title=request.title,
      description=request.description,
      severity=request.severity,
      original_payload=original_payload,
    )
    await session.commit()
    await session.refresh(event)
    await session.refresh(incident)
    return event, incident, False
  except IntegrityError as error:
    await session.rollback()
    if request.event_id is None:
      raise
    existing_event = await session.scalar(
      select(SourceEvent).where(
        SourceEvent.source_id == source_id,
        SourceEvent.external_event_id == request.event_id,
      ),
    )
    if existing_event is None:
      raise error
    existing_incident = await session.scalar(
      select(Incident).where(Incident.source_event_id == existing_event.id),
    )
    if existing_incident is None:
      existing_incident = await create_webhook_incident(
        session,
        project_id=existing_event.project_id,
        environment_id=existing_event.environment_id,
        source_event_id=existing_event.id,
        incident_type=existing_event.event_type,
        title=existing_event.title,
        description=existing_event.description,
        severity=existing_event.severity,
        original_payload=existing_event.original_payload,
      )
      await session.commit()
      await session.refresh(existing_incident)
    return existing_event, existing_incident, True


async def list_project_events(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  limit: int,
) -> list[SourceEvent]:
  await get_accessible_project(session, project_id, user)
  result = await session.scalars(
    select(SourceEvent)
    .where(SourceEvent.project_id == project_id)
    .order_by(SourceEvent.received_at.desc(), SourceEvent.id)
    .limit(limit),
  )
  return list(result)


async def get_project_event(
  session: AsyncSession,
  project_id: uuid.UUID,
  event_id: uuid.UUID,
  user: User,
) -> SourceEvent:
  await get_accessible_project(session, project_id, user)
  event = await session.scalar(
    select(SourceEvent).where(
      SourceEvent.id == event_id,
      SourceEvent.project_id == project_id,
    ),
  )
  if event is None:
    raise SourceNotFoundError("Event not found")
  return event
