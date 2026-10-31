import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  DockerIntegrationError,
  GitHubConflictError,
  GitHubIntegrationError,
  GitHubNotFoundError,
  LokiIntegrationError,
  RateLimitExceededError,
  SourceConfigurationError,
  SourceNotFoundError,
  TraceIntegrationError,
)
from app.db.incident import Incident, IncidentEvidence
from app.db.user import User
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  IntegrationInvestigationResult,
)
from app.services import github_project_service
from app.services.docker_service import (
  collect_docker_investigation,
  persist_docker_investigation,
)
from app.services.incident_service import get_incident_log_labels
from app.services.loki_service import (
  LokiConnection,
  persist_loki_evidence,
  query_loki,
)
from app.services.redis_service import rate_limit_loki_queries
from app.services.source_service import (
  get_project_docker_source,
  get_project_loki_source,
  get_project_trace_source,
)
from app.services.trace_service import TraceQuery, retrieve_incident_traces


def _failure(error: Exception) -> IntegrationInvestigationResult:
  if isinstance(error, RateLimitExceededError):
    detail = str(error)
  elif isinstance(error, (SourceNotFoundError, SourceConfigurationError)):
    detail = str(error)
  elif isinstance(error, (TraceIntegrationError, LokiIntegrationError,
                           DockerIntegrationError, GitHubIntegrationError)):
    detail = error.detail
  elif isinstance(error, (GitHubConflictError, GitHubNotFoundError)):
    detail = str(error)
  else:
    raise error
  return IntegrationInvestigationResult(status="unavailable", detail=detail)


async def _rollback_and_refresh_user(
  session: AsyncSession,
  user: User,
) -> None:
  await session.rollback()
  await session.refresh(user)


async def _persist_github_evidence(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  repository_id: int,
  context: dict[str, Any],
) -> IncidentEvidence:
  incident = await session.scalar(
    select(Incident)
    .where(
      Incident.id == incident_id,
      Incident.project_id == project_id,
    )
    .with_for_update(),
  )
  if incident is None:
    raise SourceConfigurationError("Incident changed during GitHub investigation")

  event_id = context["event_id"]
  query_hash = hashlib.sha256(
    f"github:{repository_id}:{event_id}".encode("utf-8"),
  ).hexdigest()
  now = datetime.now(UTC).isoformat()
  original = {
    "event_id": event_id,
    "context": context,
  }
  normalized = {
    "source": "github",
    "repository_id": repository_id,
    "repository": context["repository"],
    "event_id": event_id,
    "workflow_run": context["workflow_run"],
    "jobs": context["jobs"],
    "commit": context["commit"],
    "logs_available": context["logs_available"],
    "logs_truncated": context["logs_truncated"],
    "retrieved_at": now,
    "query_hash": query_hash,
  }
  evidence = await session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_id == incident.id,
      IncidentEvidence.evidence_type == "github_context",
      IncidentEvidence.query_hash == query_hash,
    ),
  )
  if evidence is None:
    evidence = IncidentEvidence(
      incident_id=incident.id,
      query_hash=query_hash,
      evidence_type="github_context",
      original_content=original,
      normalized_content=normalized,
    )
    session.add(evidence)
  else:
    evidence.original_content = original
    evidence.normalized_content = normalized
  try:
    await session.commit()
  except IntegrityError:
    await session.rollback()
    evidence = await session.scalar(
      select(IncidentEvidence).where(
        IncidentEvidence.incident_id == incident_id,
        IncidentEvidence.evidence_type == "github_context",
        IncidentEvidence.query_hash == query_hash,
      ),
    )
    if evidence is None:
      raise
    evidence.original_content = original
    evidence.normalized_content = normalized
    await session.commit()
  await session.refresh(evidence)
  return evidence


async def investigate_incident_integrations(
  session: AsyncSession,
  redis: Redis,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User,
  request: CombinedIncidentInvestigationRequest,
) -> tuple[str, dict[str, IntegrationInvestigationResult]]:
  results: dict[str, IntegrationInvestigationResult] = {}
  existing_alerts = list(
    await session.scalars(
      select(IncidentEvidence).where(
        IncidentEvidence.incident_id == incident_id,
      ),
    ),
  )
  alert_types = {
    item.evidence_type: item
    for item in existing_alerts
    if item.evidence_type in {
      "grafana_notification",
      "alertmanager_notification",
    }
  }
  for evidence_type, integration_name in (
    ("grafana_notification", "grafana"),
    ("alertmanager_notification", "alertmanager"),
  ):
    item = alert_types.get(evidence_type)
    results[integration_name] = IntegrationInvestigationResult(
      status="included" if item else "not_configured",
      evidence_id=item.id if item else None,
      detail=(
        "Existing incident alert evidence is included in the response."
        if item
        else "No matching alert evidence is attached to this incident."
      ),
    )
  results["prometheus"] = IntegrationInvestigationResult(
    status="not_configured",
    detail=(
      "Prometheus metrics are available through the incident tool registry. "
      "This combined endpoint does not execute or persist Prometheus queries "
      "until M3 evidence integration; alert metadata is included when present "
      "in Grafana or Alertmanager evidence."
    ),
  )

  if request.traces is not None:
    try:
      source = await get_project_trace_source(
        session,
        project_id,
        request.traces.source_id,
        user,
      )
      query = request.traces
      service_name = query.service_name or (
        source.trace_service_name if query.trace_id is None else None
      )
      resource_attributes = (
        dict(query.resource_attributes)
        if query.trace_id is not None
        else {
          **(source.trace_resource_attributes or {}),
          **query.resource_attributes,
        }
      )
      if query.trace_id is None and not (
        service_name or resource_attributes or query.span_attributes
      ):
        results["traces"] = IntegrationInvestigationResult(
          status="unavailable",
          detail=(
            "Provide a trace ID, service name, or resource/span attributes; "
            "unfiltered trace searches are not allowed."
          ),
        )
      elif query.end > datetime.now(UTC) + timedelta(minutes=1):
        results["traces"] = IntegrationInvestigationResult(
          status="unavailable",
          detail="Trace query times cannot be in the future.",
        )
      else:
        trace_query = TraceQuery(
          trace_id=query.trace_id,
          service_name=service_name,
          span_status=query.span_status,
          resource_attributes=resource_attributes,
          span_attributes=dict(query.span_attributes),
          start=query.start,
          end=query.end,
          limit=query.limit,
        )
        _trace_result, evidence = await retrieve_incident_traces(
          session,
          redis,
          project_id,
          incident_id,
          source,
          trace_query,
        )
        results["traces"] = IntegrationInvestigationResult(
          status=(
            "success"
            if _trace_result.traces
            else "empty"
          ),
          evidence_id=evidence.id,
        )
        await session.refresh(user)
    except (
      SourceNotFoundError,
      SourceConfigurationError,
      TraceIntegrationError,
      RateLimitExceededError,
    ) as error:
      results["traces"] = _failure(error)
      await _rollback_and_refresh_user(session, user)

  if request.loki is not None:
    try:
      source = await get_project_loki_source(
        session,
        project_id,
        request.loki.source_id,
        user,
      )
      query = request.loki
      incident_labels = await get_incident_log_labels(session, incident_id)
      if not incident_labels:
        results["loki"] = IntegrationInvestigationResult(
          status="unavailable",
          detail="Incident has no Grafana or Alertmanager labels for Loki correlation.",
        )
      elif any(
        incident_labels.get(key) != value
        for key, value in query.labels.items()
      ):
        results["loki"] = IntegrationInvestigationResult(
          status="unavailable",
          detail="Loki selector labels must match labels recorded on this incident.",
        )
      elif query.end > datetime.now(UTC) + timedelta(minutes=1):
        results["loki"] = IntegrationInvestigationResult(
          status="unavailable",
          detail="Loki query times cannot be in the future.",
        )
      else:
        await rate_limit_loki_queries(redis, source.id)
        connection = LokiConnection(
          base_url=source.loki_url or "",
          tenant_id=source.loki_tenant_id,
          auth_type=source.loki_auth_type or "none",
          auth_ciphertext=source.loki_auth_ciphertext,
        )
        source_id = source.id
        selector = "{" + ",".join(
          f"{key}={json.dumps(value, ensure_ascii=False)}"
          for key, value in sorted(query.labels.items())
        ) + "}"
        await _rollback_and_refresh_user(session, user)
        loki_result = await query_loki(
          connection,
          selector,
          query.start,
          query.end,
          query.limit,
        )
        evidence = await persist_loki_evidence(
          session,
          project_id,
          incident_id,
          source_id,
          query.labels,
          loki_result,
        )
        results["loki"] = IntegrationInvestigationResult(
          status="success" if loki_result.entries else "empty",
          evidence_id=evidence.id,
        )
    except (
      SourceNotFoundError,
      SourceConfigurationError,
      LokiIntegrationError,
      RateLimitExceededError,
    ) as error:
      results["loki"] = _failure(error)
      await _rollback_and_refresh_user(session, user)

  if request.docker is not None:
    try:
      source = await get_project_docker_source(
        session,
        project_id,
        request.docker.source_id,
        user,
      )
      source_id = source.id
      await _rollback_and_refresh_user(session, user)
      investigation = await collect_docker_investigation(
        source_id,
        project_id,
        request.docker.container_id,
        request.docker.log_tail_lines,
      )
      evidence = await persist_docker_investigation(
        session,
        project_id,
        incident_id,
        source_id,
        investigation,
        request.docker.log_tail_lines,
      )
      results["docker"] = IntegrationInvestigationResult(
        status=investigation["status"],
        evidence_id=evidence.id,
        detail=(
          "; ".join(error["detail"] for error in investigation["errors"])
          or None
        ),
      )
    except (
      SourceNotFoundError,
      SourceConfigurationError,
      DockerIntegrationError,
    ) as error:
      results["docker"] = _failure(error)
      await _rollback_and_refresh_user(session, user)

  if request.github is not None:
    try:
      await _rollback_and_refresh_user(session, user)
      context = await github_project_service.get_workflow_event_investigation(
        session,
        project_id,
        request.github.repository_id,
        request.github.event_id,
        user,
      )
      evidence = await _persist_github_evidence(
        session,
        project_id,
        incident_id,
        request.github.repository_id,
        context,
      )
      results["github"] = IntegrationInvestigationResult(
        status="success",
        evidence_id=evidence.id,
      )
    except (
      GitHubConflictError,
      GitHubIntegrationError,
      GitHubNotFoundError,
      SourceConfigurationError,
    ) as error:
      results["github"] = _failure(error)
      await _rollback_and_refresh_user(session, user)

  requested = [
    result.status
    for name, result in results.items()
    if name in {"traces", "loki", "docker", "github"}
  ]
  if all(status in {"success", "empty"} for status in requested):
    aggregate_status = "success"
  elif any(status in {"success", "empty", "partial"} for status in requested):
    aggregate_status = "partial"
  else:
    aggregate_status = "unavailable"
  return aggregate_status, results
