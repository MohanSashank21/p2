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
  ProjectNotFoundError,
  RateLimitExceededError,
  SourceConflictError,
  SourceCredentialError,
  SourceNotFoundError,
)
from app.db.database import get_db
from app.db.incident_source import IncidentSource, SourceEvent
from app.db.redis import get_redis
from app.db.user import User
from app.schemas.source_schema import (
  IncomingSourceEvent,
  SourceCreateRequest,
  SourceCredentialResponse,
  SourceEventAcceptedResponse,
  SourceEventDetailResponse,
  SourceEventResponse,
  SourceResponse,
)
from app.services.redis_service import rate_limit_source_events
from app.services.source_service import (
  authenticate_source,
  create_source,
  disable_source,
  get_project_event,
  list_project_events,
  list_sources,
  receive_source_event,
  rotate_source_credential,
)

router = APIRouter(tags=["event sources"])
MAX_SOURCE_EVENT_BYTES = 1_048_576
source_bearer = HTTPBearer(
  scheme_name="SourceCredential",
  description="Bearer credential returned when the project source is created.",
  auto_error=False,
)


def _source_response(source: IncidentSource) -> SourceResponse:
  return SourceResponse(
    id=source.id,
    project_id=source.project_id,
    environment_id=source.environment_id,
    name=source.name,
    source_type=source.source_type,
    enabled=source.enabled,
    created_at=source.created_at,
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


async def _parse_event_body(request: Request) -> tuple[IncomingSourceEvent, dict]:
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
      status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
      detail=details,
    ) from error
  return event, payload


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
  if credentials is None or not credentials.credentials.strip():
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Source credential required",
      headers={"WWW-Authenticate": "Bearer"},
    )
  try:
    source = await authenticate_source(
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

  try:
    await rate_limit_source_events(redis, source.id)
  except RateLimitExceededError as error:
    raise HTTPException(
      status_code=status.HTTP_429_TOO_MANY_REQUESTS,
      detail=str(error),
      headers={"Retry-After": "60"},
    ) from error

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
