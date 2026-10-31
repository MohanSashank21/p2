import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.exceptions import (
  PermissionDeniedError,
  LokiIntegrationError,
  PrometheusIntegrationError,
  ProjectNotFoundError,
  RateLimitExceededError,
  SourceConflictError,
  SourceConfigurationError,
  SourceCredentialError,
  SourceNotFoundError,
  TraceIntegrationError,
)
from app.db.database import get_db
from app.db.incident_source import IncidentSource, SourceEvent
from app.db.redis import get_redis
from app.db.user import User
from app.schemas.source_schema import (
  AlertmanagerAlertResult,
  AlertmanagerWebhookPayload,
  AlertmanagerWebhookResponse,
  GrafanaWebhookPayload,
  GrafanaWebhookResponse,
  IncomingSourceEvent,
  SourceCreateRequest,
  SourceCredentialResponse,
  SourceEventAcceptedResponse,
  SourceEventDetailResponse,
  SourceEventResponse,
  SourceResponse,
  LokiSourceConfigurationRequest,
  PrometheusSourceConfigurationRequest,
  TraceSourceConfigurationRequest,
)
from app.services.redis_service import rate_limit_source_events
from app.services.alertmanager_service import receive_provider_alert_payload
from app.services.loki_service import automatically_retrieve_loki_logs
from app.services.source_service import (
  authenticate_source,
  create_source,
  disable_source,
  get_project_event,
  list_project_events,
  list_sources,
  receive_source_event,
  rotate_source_credential,
  update_trace_source,
  update_loki_source,
  update_prometheus_source,
  validate_prometheus_source_connection,
  validate_trace_source_connection,
)

router = APIRouter(tags=["event sources"])
MAX_SOURCE_EVENT_BYTES = 1_048_576
source_bearer = HTTPBearer(
  scheme_name="SourceCredential",
  description="Bearer credential returned when the project source is created.",
  auto_error=False,
)


def _inline_schema_definitions(schema: dict) -> dict:
  definitions = schema.pop("$defs", {})

  def expand(value):
    if isinstance(value, list):
      return [expand(item) for item in value]
    if not isinstance(value, dict):
      return value
    reference = value.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/$defs/"):
      definition = definitions.get(reference.rsplit("/", 1)[-1], {})
      expanded = expand(definition)
      expanded.update(
        {
          key: expand(item)
          for key, item in value.items()
          if key != "$ref"
        },
      )
      return expanded
    return {key: expand(item) for key, item in value.items()}

  return expand(schema)


def _source_response(source: IncidentSource) -> SourceResponse:
  return SourceResponse(
    id=source.id,
    project_id=source.project_id,
    environment_id=source.environment_id,
    name=source.name,
    source_type=source.source_type,
    enabled=source.enabled,
    created_at=source.created_at,
    loki_url=source.loki_url,
    loki_tenant_id=source.loki_tenant_id,
    loki_auth_type=source.loki_auth_type,
    loki_auth_configured=source.loki_auth_ciphertext is not None,
    prometheus_url=source.prometheus_url,
    prometheus_auth_type=source.prometheus_auth_type,
    prometheus_auth_configured=source.prometheus_auth_ciphertext is not None,
    prometheus_connection_status=source.prometheus_connection_status,
    prometheus_last_checked_at=source.prometheus_last_checked_at,
    trace_backend=source.trace_backend,
    trace_url=source.trace_url,
    trace_tenant_id=source.trace_tenant_id,
    trace_auth_type=source.trace_auth_type,
    trace_auth_configured=source.trace_auth_ciphertext is not None,
    trace_service_name=source.trace_service_name,
    trace_resource_attributes=source.trace_resource_attributes or {},
    trace_connection_status=source.trace_connection_status,
    trace_last_checked_at=source.trace_last_checked_at,
  )


def _credential_response(
  source: IncidentSource,
  credential: str,
) -> SourceCredentialResponse:
  return SourceCredentialResponse(
    **_source_response(source).model_dump(),
    credential=credential,
  )


def _event_response(
  event: SourceEvent,
  *,
  duplicate: bool = False,
) -> SourceEventResponse:
  return SourceEventResponse(
    id=event.id,
    source_id=event.source_id,
    project_id=event.project_id,
    environment_id=event.environment_id,
    external_event_id=event.external_event_id,
    event_type=event.event_type,
    title=event.title,
    description=event.description,
    severity=event.severity,
    received_at=event.received_at,
    duplicate=duplicate,
  )


async def _limited_body(request: Request) -> bytes:
  chunks: list[bytes] = []
  size = 0
  async for chunk in request.stream():
    size += len(chunk)
    if size > MAX_SOURCE_EVENT_BYTES:
      raise HTTPException(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        detail="Event payload exceeds the 1 MiB limit",
      )
    chunks.append(chunk)
  return b"".join(chunks)


async def _automatically_retrieve_alert_logs(
  session: AsyncSession,
  redis: Redis,
  project_id: uuid.UUID,
  payload: AlertmanagerWebhookPayload | GrafanaWebhookPayload,
  results: list[AlertmanagerAlertResult],
) -> None:
  for result in results:
    if result.status != "firing" or result.incident_id is None:
      continue
    alert = next(
      (
        item
        for item in payload.alerts
        if item.fingerprint == result.fingerprint
      ),
      None,
    )
    if alert is None:
      continue
    result.loki_retrieval = await automatically_retrieve_loki_logs(
      session,
      redis,
      project_id,
      result.incident_id,
      alert.labels,
      alert.starts_at,
    )


async def _parse_json_object(request: Request) -> dict:
  raw_body = await _limited_body(request)
  try:
    payload = json.loads(raw_body)
  except (json.JSONDecodeError, UnicodeDecodeError) as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="Request body must be a JSON object",
    ) from error
  if not isinstance(payload, dict):
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="Request body must be a JSON object",
    )
  return payload


async def _parse_event_body(request: Request) -> tuple[IncomingSourceEvent, dict]:
  payload = await _parse_json_object(request)
  try:
    event = IncomingSourceEvent.model_validate(payload)
  except ValidationError as error:
    details = [
      {
        "loc": item["loc"],
        "msg": item["msg"],
        "type": item["type"],
      }
      for item in error.errors()
    ]
    raise HTTPException(
      status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
      detail=details,
    ) from error
  return event, payload


async def _parse_alertmanager_body(
  request: Request,
) -> tuple[AlertmanagerWebhookPayload, dict]:
  payload = await _parse_json_object(request)
  try:
    event = AlertmanagerWebhookPayload.model_validate(payload)
  except ValidationError as error:
    details = [
      {
        "loc": item["loc"],
        "msg": item["msg"],
        "type": item["type"],
      }
      for item in error.errors()
    ]
    raise HTTPException(
      status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
      detail=details,
    ) from error
  return event, payload


async def _parse_grafana_body(
  request: Request,
) -> tuple[GrafanaWebhookPayload, dict]:
  payload = await _parse_json_object(request)
  try:
    event = GrafanaWebhookPayload.model_validate(payload)
  except ValidationError as error:
    details = [
      {
        "loc": item["loc"],
        "msg": item["msg"],
        "type": item["type"],
      }
      for item in error.errors()
    ]
    raise HTTPException(
      status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
      detail=details,
    ) from error
  return event, payload


async def _authenticate_webhook_source(
  source_id: uuid.UUID,
  credentials: HTTPAuthorizationCredentials | None,
  session: AsyncSession,
) -> IncidentSource:
  if credentials is None or not credentials.credentials.strip():
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Source credential required",
      headers={"WWW-Authenticate": "Bearer"},
    )
  try:
    return await authenticate_source(
      session,
      source_id,
      credentials.credentials.strip(),
    )
  except SourceCredentialError as error:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail=str(error),
      headers={"WWW-Authenticate": "Bearer"},
    ) from error


async def _rate_limit_webhook_source(
  redis: Redis,
  source_id: uuid.UUID,
) -> None:
  try:
    await rate_limit_source_events(redis, source_id)
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=status.HTTP_429_TOO_MANY_REQUESTS,
      detail=str(error),
      headers={"Retry-After": "60"},
    ) from error


def _raise_project_access_error(error: Exception) -> HTTPException:
  if isinstance(error, ProjectNotFoundError):
    return HTTPException(status_code=404, detail=str(error))
  if isinstance(error, PermissionDeniedError):
    return HTTPException(status_code=403, detail=str(error))
  raise error


@router.post(
  "/projects/{project_id}/sources",
  response_model=SourceCredentialResponse,
  status_code=status.HTTP_201_CREATED,
)
async def create_project_source(
  project_id: uuid.UUID,
  request: SourceCreateRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceCredentialResponse:
  try:
    source, credential = await create_source(session, project_id, user, request)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceConflictError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except LokiIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  except PrometheusIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  except TraceIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return _credential_response(source, credential)


@router.get(
  "/projects/{project_id}/sources",
  response_model=list[SourceResponse],
)
async def list_project_sources(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[SourceResponse]:
  try:
    sources = await list_sources(session, project_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  return [_source_response(source) for source in sources]


@router.post(
  "/projects/{project_id}/sources/{source_id}/rotate-credential",
  response_model=SourceCredentialResponse,
)
async def rotate_project_source_credential(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceCredentialResponse:
  try:
    source, credential = await rotate_source_credential(
      session,
      project_id,
      source_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return _credential_response(source, credential)


@router.post(
  "/projects/{project_id}/sources/{source_id}/disable",
  response_model=SourceResponse,
)
async def disable_project_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await disable_source(session, project_id, source_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return _source_response(source)


@router.post(
  "/projects/{project_id}/sources/{source_id}/prometheus/validate",
  response_model=SourceResponse,
)
async def validate_prometheus_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await validate_prometheus_source_connection(
      session,
      project_id,
      source_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except PrometheusIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return _source_response(source)


@router.patch(
  "/projects/{project_id}/sources/{source_id}/loki",
  response_model=SourceResponse,
)
async def configure_loki_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  request: LokiSourceConfigurationRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await update_loki_source(
      session,
      project_id,
      source_id,
      user,
      request,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except LokiIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return _source_response(source)


@router.patch(
  "/projects/{project_id}/sources/{source_id}/prometheus",
  response_model=SourceResponse,
)
async def configure_prometheus_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  request: PrometheusSourceConfigurationRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await update_prometheus_source(
      session,
      project_id,
      source_id,
      user,
      request,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except PrometheusIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return _source_response(source)


@router.patch(
  "/projects/{project_id}/sources/{source_id}/traces",
  response_model=SourceResponse,
)
async def configure_trace_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  request: TraceSourceConfigurationRequest,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await update_trace_source(
      session,
      project_id,
      source_id,
      user,
      request,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except (SourceConfigurationError, TraceIntegrationError) as error:
    status_code = (
      error.status_code
      if isinstance(error, TraceIntegrationError)
      else status.HTTP_409_CONFLICT
    )
    detail = error.detail if isinstance(error, TraceIntegrationError) else str(error)
    raise HTTPException(status_code=status_code, detail=detail) from error
  return _source_response(source)


@router.post(
  "/projects/{project_id}/sources/{source_id}/traces/validate",
  response_model=SourceResponse,
)
async def validate_trace_source(
  project_id: uuid.UUID,
  source_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceResponse:
  try:
    source = await validate_trace_source_connection(
      session,
      project_id,
      source_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except SourceConfigurationError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except TraceIntegrationError as error:
    raise HTTPException(
      status_code=error.status_code,
      detail=error.detail,
    ) from error
  return _source_response(source)


@router.post(
  "/webhooks/sources/{source_id}",
  response_model=SourceEventAcceptedResponse,
  status_code=status.HTTP_201_CREATED,
  responses={200: {"model": SourceEventAcceptedResponse}},
  openapi_extra={
    "requestBody": {
      "required": True,
      "content": {
        "application/json": {
          "schema": IncomingSourceEvent.model_json_schema(),
          "example": {
            "event_id": "alert-2026-01",
            "event_type": "infrastructure",
            "title": "High memory usage",
            "description": "Memory usage exceeded the configured threshold.",
            "severity": "high",
            "labels": {"service": "payments", "environment": "production"},
          },
        },
      },
    },
  },
)
async def receive_event(
  source_id: uuid.UUID,
  request: Request,
  response: Response,
  credentials: HTTPAuthorizationCredentials | None = Depends(source_bearer),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> SourceEventAcceptedResponse:
  source = await _authenticate_webhook_source(source_id, credentials, session)
  if source.source_type != "generic_webhook":
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="This source is not configured for generic webhook events",
    )
  await _rate_limit_webhook_source(redis, source.id)

  event_request, original_payload = await _parse_event_body(request)
  event, incident, duplicate = await receive_source_event(
    session,
    source,
    event_request,
    original_payload,
  )
  if duplicate:
    response.status_code = status.HTTP_200_OK
    return SourceEventAcceptedResponse(
      event=_event_response(event, duplicate=True),
      incident_id=incident.id,
      duplicate=True,
    )
  return SourceEventAcceptedResponse(
    event=_event_response(event),
    incident_id=incident.id,
    duplicate=False,
  )


@router.post(
  "/webhooks/sources/{source_id}/alertmanager",
  response_model=AlertmanagerWebhookResponse,
  status_code=status.HTTP_200_OK,
  openapi_extra={
    "requestBody": {
      "required": True,
      "content": {
        "application/json": {
          "schema": _inline_schema_definitions(
            AlertmanagerWebhookPayload.model_json_schema(),
          ),
          "example": {
            "receiver": "opspilot",
            "status": "firing",
            "version": "4",
            "groupKey": '{}:{alertname="HighCPU"}',
            "groupLabels": {"alertname": "HighCPU"},
            "commonLabels": {"severity": "critical"},
            "commonAnnotations": {"summary": "CPU usage is high"},
            "externalURL": "http://alertmanager.example",
            "alerts": [
              {
                "status": "firing",
                "labels": {
                  "alertname": "HighCPU",
                  "severity": "critical",
                  "instance": "server-01",
                },
                "annotations": {
                  "summary": "CPU usage exceeded 90%",
                  "description": "Production CPU is above threshold.",
                },
                "startsAt": "2026-10-22T08:00:00Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example/graph",
                "fingerprint": "a1b2c3d4",
              },
            ],
          },
        },
      },
    },
  },
)
async def receive_alertmanager_event(
  source_id: uuid.UUID,
  request: Request,
  credentials: HTTPAuthorizationCredentials | None = Depends(source_bearer),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> AlertmanagerWebhookResponse:
  source = await _authenticate_webhook_source(source_id, credentials, session)
  if source.source_type != "alertmanager":
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="This source is not configured for Alertmanager",
    )
  await _rate_limit_webhook_source(redis, source.id)
  payload, original_payload = await _parse_alertmanager_body(request)
  try:
    results = await receive_provider_alert_payload(
      session,
      source,
      payload,
      original_payload,
      provider="alertmanager",
    )
  except SourceConfigurationError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="Alertmanager source changed while processing notification",
    ) from error
  await _automatically_retrieve_alert_logs(
    session,
    redis,
    source.project_id,
    payload,
    results,
  )
  return AlertmanagerWebhookResponse(
    received=len(results),
    created=sum(result.outcome == "created" for result in results),
    updated=sum(result.outcome == "updated" for result in results),
    resolved=sum(result.outcome == "resolved" for result in results),
    ignored=sum(result.outcome == "ignored" for result in results),
    alerts=results,
  )


@router.post(
  "/webhooks/sources/{source_id}/grafana",
  response_model=GrafanaWebhookResponse,
  status_code=status.HTTP_200_OK,
  openapi_extra={
    "requestBody": {
      "required": True,
      "content": {
        "application/json": {
          "schema": _inline_schema_definitions(
            GrafanaWebhookPayload.model_json_schema(),
          ),
          "example": {
            "receiver": "OpsPilot",
            "status": "firing",
            "orgId": 1,
            "version": "1",
            "groupKey": "{}:{alertname=\"HighCPU\"}",
            "groupLabels": {"alertname": "HighCPU"},
            "commonLabels": {"severity": "critical"},
            "commonAnnotations": {"summary": "CPU usage is high"},
            "externalURL": "https://grafana.example/",
            "alerts": [
              {
                "status": "firing",
                "labels": {
                  "alertname": "HighCPU",
                  "severity": "critical",
                  "instance": "server-01",
                },
                "annotations": {
                  "summary": "CPU usage exceeded 90%",
                  "description": "Production CPU is above threshold.",
                },
                "startsAt": "2026-10-22T08:00:00Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "https://grafana.example/alerting/rule",
                "fingerprint": "a1b2c3d4",
                "dashboardURL": "https://grafana.example/d/abc",
                "panelURL": "https://grafana.example/d/abc?viewPanel=1",
                "silenceURL": "https://grafana.example/alerting/silence/new",
                "imageURL": "",
                "values": {"A": 95.2},
              },
            ],
          },
        },
      },
    },
  },
)

async def receive_grafana_event(
  source_id: uuid.UUID,
  request: Request,
  credentials: HTTPAuthorizationCredentials | None = Depends(source_bearer),
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> GrafanaWebhookResponse:
  source = await _authenticate_webhook_source(source_id, credentials, session)
  if source.source_type != "grafana":
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="This source is not configured for Grafana",
    )
  await _rate_limit_webhook_source(redis, source.id)
  payload, original_payload = await _parse_grafana_body(request)
  normalized_payload = AlertmanagerWebhookPayload.model_validate(
    {
      **payload.model_dump(
        by_alias=True,
        mode="json",
        exclude={"alerts"},
      ),
      "alerts": [
        alert.model_dump(by_alias=True, mode="json")
        for alert in payload.alerts
      ],
    },
  )
  try:
    results = await receive_provider_alert_payload(
      session,
      source,
      normalized_payload,
      original_payload,
      provider="grafana",
    )
  except SourceConfigurationError as error:
    raise HTTPException(
      status_code=status.HTTP_409_CONFLICT,
      detail="Grafana source changed while processing notification",
    ) from error
  await _automatically_retrieve_alert_logs(
    session,
    redis,
    source.project_id,
    payload,
    results,
  )
  return GrafanaWebhookResponse(
    received=len(results),
    created=sum(result.outcome == "created" for result in results),
    updated=sum(result.outcome == "updated" for result in results),
    resolved=sum(result.outcome == "resolved" for result in results),
    ignored=sum(result.outcome == "ignored" for result in results),
    alerts=results,
  )


@router.get(
  "/projects/{project_id}/events",
  response_model=list[SourceEventResponse],
)
async def list_events(
  project_id: uuid.UUID,
  limit: int = Query(default=50, ge=1, le=100),
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[SourceEventResponse]:
  try:
    events = await list_project_events(session, project_id, user, limit)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  return [_event_response(event) for event in events]


@router.get(
  "/projects/{project_id}/events/{event_id}",
  response_model=SourceEventDetailResponse,
)
async def get_event(
  project_id: uuid.UUID,
  event_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> SourceEventDetailResponse:
  try:
    event = await get_project_event(session, project_id, event_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except SourceNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return SourceEventDetailResponse(
    **_event_response(event).model_dump(),
    original_payload=event.original_payload,
  )
