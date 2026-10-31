import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  LokiIntegrationError,
  PrometheusIntegrationError,
  PermissionDeniedError,
  SourceConfigurationError,
  TraceIntegrationError,
  ProjectNotFoundError,
  SourceConflictError,
  SourceCredentialError,
  SourceNotFoundError,
)
from app.db.environment import Environment
from app.db.incident import Incident
from app.db.incident_source import IncidentSource, SourceEvent
from app.db.user import User
from app.schemas.source_schema import (
  IncomingSourceEvent,
  LokiSourceConfigurationRequest,
  PrometheusSourceConfigurationRequest,
  SourceCreateRequest,
  TraceSourceConfigurationRequest,
)
from app.services.incident_service import create_webhook_incident
from app.services.loki_service import encrypt_loki_auth, validate_loki_url
from app.services.project_service import get_accessible_project
from app.services.prometheus_service import (
  encrypt_prometheus_auth,
  validate_prometheus_url,
)
from app.services.trace_service import (
  TempoConnection,
  encrypt_trace_auth,
  validate_tempo_connection,
  validate_tempo_url,
)


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

  loki_url = None
  loki_auth_ciphertext = None
  prometheus_url = None
  prometheus_auth_ciphertext = None
  trace_url = None
  trace_auth_ciphertext = None
  if request.source_type == "loki":
    if request.loki_url is None:
      raise LokiIntegrationError(422, "loki_url is required for Loki sources")
    validate_loki_url(str(request.loki_url))
    loki_url = str(request.loki_url).rstrip("/")
    loki_auth_ciphertext = encrypt_loki_auth(
      request.loki_auth_type,
      request.loki_username,
      request.loki_password,
      request.loki_bearer_token,
    )
  if request.source_type == "traces":
    if request.trace_url is None:
      raise TraceIntegrationError(422, "trace_url is required for trace sources")
    validate_tempo_url(str(request.trace_url))
    trace_url = str(request.trace_url).rstrip("/")
    trace_auth_ciphertext = encrypt_trace_auth(
      request.trace_auth_type,
      request.trace_username,
      request.trace_password,
      request.trace_bearer_token,
    )
  if request.source_type == "prometheus":
    if request.prometheus_url is None:
      raise PrometheusIntegrationError(
        422,
        "prometheus_url is required for Prometheus sources",
      )
    validate_prometheus_url(str(request.prometheus_url))
    prometheus_url = str(request.prometheus_url).rstrip("/")
    prometheus_auth_ciphertext = encrypt_prometheus_auth(
      request.prometheus_auth_type,
      request.prometheus_username,
      request.prometheus_password,
      request.prometheus_bearer_token,
    )

  credential = secrets.token_urlsafe(32)
  source = IncidentSource(
    project_id=project_id,
    environment_id=request.environment_id,
    name=request.name,
    source_type=request.source_type,
    loki_url=loki_url,
    loki_tenant_id=request.loki_tenant_id,
    loki_auth_type=(
      request.loki_auth_type if request.source_type == "loki" else None
    ),
    loki_auth_ciphertext=loki_auth_ciphertext,
    prometheus_url=prometheus_url,
    prometheus_auth_type=(
      request.prometheus_auth_type if request.source_type == "prometheus" else None
    ),
    prometheus_auth_ciphertext=prometheus_auth_ciphertext,
    trace_backend=request.trace_backend if request.source_type == "traces" else None,
    trace_url=trace_url,
    trace_tenant_id=(
      request.trace_tenant_id if request.source_type == "traces" else None
    ),
    trace_auth_type=(
      request.trace_auth_type if request.source_type == "traces" else None
    ),
    trace_auth_ciphertext=trace_auth_ciphertext,
    trace_service_name=(
      request.trace_service_name if request.source_type == "traces" else None
    ),
    trace_resource_attributes=(
      request.trace_resource_attributes if request.source_type == "traces" else None
    ),
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


async def update_prometheus_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
  request: PrometheusSourceConfigurationRequest,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  if source.source_type != "prometheus":
    raise SourceNotFoundError("Prometheus source not found")
  validate_prometheus_url(str(request.prometheus_url))
  auth_ciphertext = encrypt_prometheus_auth(
    request.prometheus_auth_type,
    request.prometheus_username,
    request.prometheus_password,
    request.prometheus_bearer_token,
  )
  source.prometheus_url = str(request.prometheus_url).rstrip("/")
  source.prometheus_auth_type = request.prometheus_auth_type
  source.prometheus_auth_ciphertext = auth_ciphertext
  source.enabled = request.enabled
  await session.commit()
  await session.refresh(source)
  return source


async def update_loki_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
  request: LokiSourceConfigurationRequest,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  if source.source_type != "loki":
    raise SourceNotFoundError("Loki source not found")
  validate_loki_url(str(request.loki_url))
  source.loki_url = str(request.loki_url).rstrip("/")
  source.loki_tenant_id = request.loki_tenant_id
  source.loki_auth_type = request.loki_auth_type
  source.loki_auth_ciphertext = encrypt_loki_auth(
    request.loki_auth_type,
    request.loki_username,
    request.loki_password,
    request.loki_bearer_token,
  )
  source.enabled = request.enabled
  await session.commit()
  await session.refresh(source)
  return source


async def update_trace_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
  request: TraceSourceConfigurationRequest,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  if source.source_type != "traces":
    raise SourceNotFoundError("Trace source not found")
  validate_tempo_url(str(request.trace_url))
  source.trace_backend = request.trace_backend
  source.trace_url = str(request.trace_url).rstrip("/")
  source.trace_tenant_id = request.trace_tenant_id
  source.trace_auth_type = request.trace_auth_type
  source.trace_auth_ciphertext = encrypt_trace_auth(
    request.trace_auth_type,
    request.trace_username,
    request.trace_password,
    request.trace_bearer_token,
  )
  source.trace_service_name = request.trace_service_name
  source.trace_resource_attributes = request.trace_resource_attributes
  source.trace_connection_status = "not_checked"
  source.trace_last_checked_at = None
  source.enabled = request.enabled
  await session.commit()
  await session.refresh(source)
  return source


async def get_project_prometheus_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  await get_accessible_project(session, project_id, user)
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "prometheus",
    ),
  )
  if source is None:
    raise SourceNotFoundError("Prometheus source not found in this project")
  if not source.enabled:
    raise SourceConfigurationError("Prometheus source is disabled")
  if source.prometheus_url is None:
    raise SourceConfigurationError("Prometheus source is not configured")
  return source


async def get_project_trace_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  await get_accessible_project(session, project_id, user)
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "traces",
    ),
  )
  if source is None:
    raise SourceNotFoundError("Trace source not found in this project")
  if not source.enabled:
    raise SourceConfigurationError("Trace source is disabled")
  if source.trace_backend != "tempo" or source.trace_url is None:
    raise SourceConfigurationError("Trace source is not configured")
  return source


async def get_project_docker_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  await get_accessible_project(session, project_id, user)
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "docker",
    ),
  )
  if source is None:
    raise SourceNotFoundError("Docker source not found in this project")
  if not source.enabled:
    raise SourceConfigurationError("Docker source is disabled")
  return source


async def validate_trace_source_connection(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  if source.source_type != "traces":
    raise SourceNotFoundError("Trace source not found")
  if source.trace_backend != "tempo" or source.trace_url is None:
    raise SourceConfigurationError("Trace source is not configured")
  connection = TempoConnection(
    base_url=source.trace_url,
    tenant_id=source.trace_tenant_id,
    auth_type=source.trace_auth_type or "none",
    auth_ciphertext=source.trace_auth_ciphertext,
  )
  source.trace_last_checked_at = datetime.now(UTC)
  try:
    await validate_tempo_connection(connection)
  except TraceIntegrationError:
    source.trace_connection_status = "unavailable"
    await session.commit()
    raise
  source.trace_connection_status = "connected"
  await session.commit()
  await session.refresh(source)
  return source


async def get_project_loki_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  await get_accessible_project(session, project_id, user)
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "loki",
    ),
  )
  if source is None:
    raise SourceNotFoundError("Loki source not found in this project")
  if not source.enabled:
    raise SourceConfigurationError("Loki source is disabled")
  if source.loki_url is None or source.loki_auth_type is None:
    raise SourceConfigurationError("Loki source is not configured")
  return source


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
