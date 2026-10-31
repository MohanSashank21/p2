import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  IncidentNotFoundError,
  InvalidIncidentTransitionError,
  ProjectNotFoundError,
)
from app.db.environment import Environment
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import AlertmanagerAlert
from app.db.user import User
from app.schemas.incident_schema import (
  IncidentCreateRequest,
  IncidentStatusUpdateRequest,
)
from app.services.project_service import get_accessible_project

_ALLOWED_STATUS_TRANSITIONS = {
  "open": {"acknowledged", "resolved"},
  "acknowledged": {"open", "resolved"},
  "resolved": {"open"},
}


async def _validate_environment(
  session: AsyncSession,
  project_id: uuid.UUID,
  environment_id: uuid.UUID | None,
) -> None:
  if environment_id is None:
    return
  environment = await session.scalar(
    select(Environment.id).where(
      Environment.id == environment_id,
      Environment.project_id == project_id,
    ),
  )
  if environment is None:
    raise ProjectNotFoundError("Environment not found in this project")


async def create_manual_incident(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  request: IncidentCreateRequest,
) -> Incident:
  await get_accessible_project(session, project_id, user)
  await _validate_environment(session, project_id, request.environment_id)

  incident = Incident(
    project_id=project_id,
    environment_id=request.environment_id,
    reported_by_user_id=user.id,
    source_type="manual",
    incident_type=request.incident_type,
    title=request.title,
    description=request.description,
    severity=request.severity,
    status="open",
  )
  session.add(incident)
  await session.flush()
  session.add(
    IncidentEvidence(
      incident_id=incident.id,
      evidence_type="manual_report",
      original_content=request.model_dump(mode="json"),
      normalized_content={
        "incident_type": request.incident_type,
        "title": request.title,
        "description": request.description,
        "severity": request.severity,
      },
    ),
  )
  await session.commit()
  await session.refresh(incident)
  return incident


async def create_webhook_incident(
  session: AsyncSession,
  *,
  project_id: uuid.UUID,
  environment_id: uuid.UUID | None,
  source_event_id: uuid.UUID,
  incident_type: str,
  title: str,
  description: str | None,
  severity: str,
  original_payload: dict,
) -> Incident:
  incident = Incident(
    project_id=project_id,
    environment_id=environment_id,
    source_event_id=source_event_id,
    source_type="generic_webhook",
    incident_type=incident_type,
    title=title,
    description=description,
    severity=severity,
    status="open",
  )
  session.add(incident)
  await session.flush()
  session.add(
    IncidentEvidence(
      incident_id=incident.id,
      source_event_id=source_event_id,
      evidence_type="webhook_payload",
      original_content=original_payload,
      normalized_content={
        "event_type": incident_type,
        "title": title,
        "description": description,
        "severity": severity,
      },
    ),
  )
  return incident


async def list_project_incidents(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  limit: int,
) -> list[Incident]:
  await get_accessible_project(session, project_id, user)
  result = await session.scalars(
    select(Incident)
    .where(Incident.project_id == project_id)
    .order_by(Incident.created_at.desc(), Incident.id)
    .limit(limit),
  )
  return list(result)


async def get_project_incident(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User,
) -> Incident:
  await get_accessible_project(session, project_id, user)
  incident = await session.scalar(
    select(Incident).where(
      Incident.id == incident_id,
      Incident.project_id == project_id,
    ),
  )
  if incident is None:
    raise IncidentNotFoundError("Incident not found")
  return incident


async def update_incident_status(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User,
  request: IncidentStatusUpdateRequest,
) -> Incident:
  incident = await get_project_incident(
    session,
    project_id,
    incident_id,
    user,
  )
  if request.status != incident.status:
    if request.status not in _ALLOWED_STATUS_TRANSITIONS[incident.status]:
      raise InvalidIncidentTransitionError(
        f"Cannot transition incident from {incident.status} to {request.status}",
      )
    if request.status == "resolved":
      active_alerts = await session.scalar(
        select(AlertmanagerAlert.id)
        .where(
          AlertmanagerAlert.incident_id == incident.id,
          AlertmanagerAlert.status == "firing",
        )
        .limit(1),
      )
      if active_alerts is not None:
        raise InvalidIncidentTransitionError(
          "Cannot resolve an incident while linked monitoring alerts are firing",
        )
    incident.status = request.status
    incident.resolved_at = (
      datetime.now(UTC) if request.status == "resolved" else None
    )
    await session.commit()
    await session.refresh(incident)
  return incident


async def list_incident_evidence(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User,
  *,
  limit: int | None = None,
  offset: int = 0,
  evidence_types: set[str] | None = None,
) -> list[IncidentEvidence]:
  if limit is not None and limit < 1:
    raise ValueError("Evidence limit must be positive")
  if offset < 0:
    raise ValueError("Evidence offset cannot be negative")
  await get_project_incident(session, project_id, incident_id, user)
  statement = (
    select(IncidentEvidence)
    .where(IncidentEvidence.incident_id == incident_id)
  )
  if evidence_types is not None:
    statement = statement.where(IncidentEvidence.evidence_type.in_(evidence_types))
  statement = statement.order_by(
    IncidentEvidence.created_at,
    IncidentEvidence.id,
  )
  if limit is not None:
    statement = statement.limit(limit)
  if offset:
    statement = statement.offset(offset)
  result = await session.scalars(statement)
  return list(result)


async def get_incident_log_labels(
  session: AsyncSession,
  incident_id: uuid.UUID,
) -> dict[str, str]:
  result = await session.scalars(
    select(IncidentEvidence)
    .where(
      IncidentEvidence.incident_id == incident_id,
      IncidentEvidence.evidence_type != "loki_logs",
    )
    .order_by(IncidentEvidence.created_at.desc(), IncidentEvidence.id.desc()),
  )
  for evidence in result:
    labels = evidence.normalized_content.get("labels")
    if not isinstance(labels, dict):
      labels = evidence.original_content.get("labels")
    if not isinstance(labels, dict):
      alert = evidence.original_content.get("alert")
      if isinstance(alert, dict):
        labels = alert.get("labels")
    if isinstance(labels, dict):
      return {
        key: value
        for key, value in labels.items()
        if isinstance(key, str) and isinstance(value, str)
      }
  return {}
