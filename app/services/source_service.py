import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime

from pydantic import AnyHttpUrl, TypeAdapter
from sqlalchemy import exists, select
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
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource, ProviderAlert, SourceEvent
from app.db.user import User
from app.schemas.source_schema import (
  IncomingSourceEvent,
  LokiSourceConfigurationRequest,
  PrometheusSourceConfigurationRequest,
  SourceCreateRequest,
  SourcePatchRequest,
  TraceSourceConfigurationRequest,
  _validate_loki_auth,
  _validate_prometheus_auth,
  _validate_prometheus_url,
  _validate_trace_configuration,
)
from app.services.incident_service import create_webhook_incident
from app.services.loki_service import encrypt_loki_auth, validate_loki_url
from app.services.project_service import get_accessible_project
from app.services.prometheus_service import (
  PrometheusConnection,
  encrypt_prometheus_auth,
  validate_prometheus_connection,
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


_http_url_adapter = TypeAdapter(AnyHttpUrl)


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
  source.prometheus_connection_status = "not_checked"
  source.prometheus_last_checked_at = None
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


async def get_project_source(
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
    ),
  )
  if source is None:
    raise SourceNotFoundError("Source not found in this project")
  return source


def _update_source_auth(
  source: IncidentSource,
  request: SourcePatchRequest,
  fields_set: set[str],
  prefix: str,
) -> bool:
  auth_type_field = f"{prefix}_auth_type"
  username_field = f"{prefix}_username"
  password_field = f"{prefix}_password"
  bearer_token_field = f"{prefix}_bearer_token"
  credential_fields = {
    username_field,
    password_field,
    bearer_token_field,
  }
  if auth_type_field not in fields_set and not fields_set.intersection(
    credential_fields,
  ):
    return False

  current_auth_type = getattr(source, f"{prefix}_auth_type") or "none"
  auth_type = getattr(request, auth_type_field) or current_auth_type
  old_ciphertext = getattr(source, f"{prefix}_auth_ciphertext")
  if auth_type == "none":
    setattr(source, f"{prefix}_auth_type", "none")
    setattr(source, f"{prefix}_auth_ciphertext", None)
    return current_auth_type != "none" or old_ciphertext is not None

  credential_values = tuple(
    getattr(request, field)
    for field in (username_field, password_field, bearer_token_field)
  )
  credentials_were_provided = bool(fields_set.intersection(credential_fields))
  if auth_type == current_auth_type and not credentials_were_provided:
    return False

  try:
    _validate_prometheus_auth(auth_type, *credential_values)
  except ValueError as error:
    raise SourceConfigurationError(str(error)) from error
  if prefix == "loki":
    ciphertext = encrypt_loki_auth(auth_type, *credential_values)
  elif prefix == "prometheus":
    ciphertext = encrypt_prometheus_auth(auth_type, *credential_values)
  else:
    ciphertext = encrypt_trace_auth(auth_type, *credential_values)
  setattr(source, f"{prefix}_auth_type", auth_type)
  setattr(source, f"{prefix}_auth_ciphertext", ciphertext)
  return True


async def update_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
  request: SourcePatchRequest,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  fields_set = request.model_fields_set
  provider_fields = fields_set.difference(
    {"name", "enabled", "environment_id"},
  )
  provider_fields_by_type = {
    "loki": {
      "loki_url",
      "loki_tenant_id",
      "loki_auth_type",
      "loki_username",
      "loki_password",
      "loki_bearer_token",
    },
    "prometheus": {
      "prometheus_url",
      "prometheus_auth_type",
      "prometheus_username",
      "prometheus_password",
      "prometheus_bearer_token",
    },
    "traces": {
      "trace_backend",
      "trace_url",
      "trace_tenant_id",
      "trace_auth_type",
      "trace_username",
      "trace_password",
      "trace_bearer_token",
      "trace_service_name",
      "trace_resource_attributes",
    },
  }
  if not provider_fields.issubset(
    provider_fields_by_type.get(source.source_type, set()),
  ):
    raise SourceConfigurationError(
      f"Provider settings cannot be updated for {source.source_type} sources",
    )

  if "name" in fields_set:
    if request.name is None:
      raise SourceConfigurationError("Source name cannot be null")
    source.name = request.name
  if "enabled" in fields_set:
    if request.enabled is None:
      raise SourceConfigurationError("Source enabled state cannot be null")
    source.enabled = request.enabled
  if "environment_id" in fields_set:
    if request.environment_id is not None:
      environment = await session.scalar(
        select(Environment.id).where(
          Environment.id == request.environment_id,
          Environment.project_id == project_id,
        ),
      )
      if environment is None:
        raise ProjectNotFoundError("Environment not found in this project")
    source.environment_id = request.environment_id

  auth_changed = False
  if source.source_type == "loki":
    url = request.loki_url or (
      _http_url_adapter.validate_python(source.loki_url)
      if source.loki_url is not None
      else None
    )
    if url is None:
      raise SourceConfigurationError("Loki source is not configured")
    if "loki_url" in fields_set:
      validate_loki_url(str(url))
      source.loki_url = str(url).rstrip("/")
    tenant_id = (
      request.loki_tenant_id
      if "loki_tenant_id" in fields_set
      else source.loki_tenant_id
    )
    try:
      _validate_loki_auth(url, tenant_id, "none", None, None, None)
    except ValueError as error:
      raise SourceConfigurationError(str(error)) from error
    source.loki_tenant_id = tenant_id
    auth_changed = _update_source_auth(source, request, fields_set, "loki")
  elif source.source_type == "prometheus":
    url = request.prometheus_url or (
      _http_url_adapter.validate_python(source.prometheus_url)
      if source.prometheus_url is not None
      else None
    )
    if url is None:
      raise SourceConfigurationError("Prometheus source is not configured")
    try:
      _validate_prometheus_url(url)
    except ValueError as error:
      raise SourceConfigurationError(str(error)) from error
    if "prometheus_url" in fields_set:
      validate_prometheus_url(str(url))
      source.prometheus_url = str(url).rstrip("/")
    auth_changed = _update_source_auth(
      source,
      request,
      fields_set,
      "prometheus",
    )
    if "prometheus_url" in fields_set or auth_changed:
      source.prometheus_connection_status = "not_checked"
      source.prometheus_last_checked_at = None
  elif source.source_type == "traces":
    url = request.trace_url or (
      _http_url_adapter.validate_python(source.trace_url)
      if source.trace_url is not None
      else None
    )
    if url is None:
      raise SourceConfigurationError("Trace source is not configured")
    tenant_id = (
      request.trace_tenant_id
      if "trace_tenant_id" in fields_set
      else source.trace_tenant_id
    )
    service_name = (
      request.trace_service_name
      if "trace_service_name" in fields_set
      else source.trace_service_name
    )
    resource_attributes = (
      request.trace_resource_attributes
      if "trace_resource_attributes" in fields_set
      else source.trace_resource_attributes or {}
    )
    try:
      _validate_trace_configuration(
        request.trace_backend or source.trace_backend or "tempo",
        url,
        tenant_id,
        "none",
        None,
        None,
        None,
        service_name,
        resource_attributes,
      )
    except ValueError as error:
      raise SourceConfigurationError(str(error)) from error
    if "trace_url" in fields_set:
      validate_tempo_url(str(url))
      source.trace_url = str(url).rstrip("/")
    if "trace_backend" in fields_set:
      source.trace_backend = request.trace_backend
    source.trace_tenant_id = tenant_id
    source.trace_service_name = service_name
    source.trace_resource_attributes = resource_attributes
    auth_changed = _update_source_auth(source, request, fields_set, "trace")
    if "trace_url" in fields_set or auth_changed:
      source.trace_connection_status = "not_checked"
      source.trace_last_checked_at = None

  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise SourceConflictError(
      "A source with this name already exists in the project",
    ) from error
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


async def validate_prometheus_source_connection(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> IncidentSource:
  source = await _get_managed_source(session, project_id, source_id, user)
  if source.source_type != "prometheus":
    raise SourceNotFoundError("Prometheus source not found")
  if source.prometheus_url is None:
    raise SourceConfigurationError("Prometheus source is not configured")

  connection = PrometheusConnection(
    base_url=source.prometheus_url,
    auth_type=source.prometheus_auth_type or "none",
    auth_ciphertext=source.prometheus_auth_ciphertext,
  )
  source.prometheus_last_checked_at = datetime.now(UTC)
  try:
    await validate_prometheus_connection(connection)
  except PrometheusIntegrationError:
    source.prometheus_connection_status = "unavailable"
    await session.commit()
    raise
  source.prometheus_connection_status = "connected"
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


async def delete_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
) -> None:
  source = await _get_managed_source(
    session,
    project_id,
    source_id,
    user,
    lock=True,
  )
  has_events = await session.scalar(
    select(exists().where(SourceEvent.source_id == source_id)),
  )
  has_alerts = await session.scalar(
    select(exists().where(ProviderAlert.source_id == source_id)),
  )
  has_evidence = await session.scalar(
    select(exists().where(IncidentEvidence.incident_source_id == source_id)),
  )
  if has_events or has_alerts or has_evidence:
    raise SourceConflictError(
      "Source has event, alert, or evidence history; disable it instead",
    )
  await session.delete(source)
  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise SourceConflictError(
      "Source acquired history and cannot be deleted; disable it instead",
    ) from error


async def _get_managed_source(
  session: AsyncSession,
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User,
  *,
  lock: bool = False,
) -> IncidentSource:
  _project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can manage event sources")
  query = select(IncidentSource).where(
    IncidentSource.id == source_id,
    IncidentSource.project_id == project_id,
  )
  if lock:
    query = query.with_for_update()
  source = await session.scalar(query)
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
