from sqlalchemy import select

from app.db.incident import IncidentEvidence
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  DockerInvestigationCriteria,
  IntegrationInvestigationResult,
)
from app.services.incident_investigation_service import (
  investigate_incident_integrations,
)
from app.tools.contracts import (
  ToolContext,
  ToolDefinition,
  ToolError,
  ToolEvidenceRef,
  ToolResult,
)
from app.tools.evidence import evidence_payload


async def _investigate_incident_container(
  context: ToolContext,
  arguments: DockerInvestigationCriteria,
) -> ToolResult:
  _aggregate_status, integrations = await investigate_incident_integrations(
    context.session,
    context.redis,
    context.project_id,
    context.incident_id,
    context.user,
    CombinedIncidentInvestigationRequest(docker=arguments),
  )
  result: IntegrationInvestigationResult = integrations["docker"]
  if result.status not in {"success", "partial", "unavailable"}:
    raise RuntimeError("Docker investigation returned an invalid status")
  if result.evidence_id is None:
    if result.status != "unavailable":
      raise RuntimeError("Docker investigation evidence was not persisted")
    return ToolResult(
      status="unavailable",
      error=ToolError(
        code="integration_unavailable",
        message=result.detail or "Docker could not collect container evidence.",
      ),
      completeness="unknown",
    )

  evidence: IncidentEvidence | None = await context.session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.id == result.evidence_id,
      IncidentEvidence.incident_id == context.incident_id,
    ),
  )
  if evidence is None:
    raise RuntimeError("Docker investigation evidence was not persisted")

  normalized = evidence.normalized_content
  retrieval_status = normalized.get("retrieval_status")
  if retrieval_status != result.status:
    raise RuntimeError("Persisted Docker evidence status does not match result")
  collected = normalized.get("evidence")
  logs = collected.get("logs") if isinstance(collected, dict) else None
  truncated = isinstance(logs, dict) and logs.get("truncated") is True
  status = (
    "partial"
    if result.status == "success" and truncated
    else result.status
  )
  detail = result.detail
  return ToolResult(
    status=status,
    data={
      "evidence": evidence_payload(evidence),
      "query_criteria": normalized.get("query_criteria"),
      "query_time_range": normalized.get("query_time_range"),
      "findings": normalized.get("findings"),
      "unavailable": normalized.get("unavailable"),
      "errors": normalized.get("errors"),
    },
    error=(
      ToolError(code="partial_collection", message=detail)
      if status == "partial" and detail
      else ToolError(
        code="integration_unavailable",
        message=detail or "Docker could not collect container evidence.",
      )
      if status == "unavailable"
      else None
    ),
    evidence=[
      ToolEvidenceRef(
        id=evidence.id,
        evidence_type=evidence.evidence_type,
        source_id=evidence.incident_source_id,
        observed_at=evidence.created_at,
      ),
    ],
    completeness="partial" if status in {"partial", "unavailable"} else "complete",
    truncated=truncated,
    content_is_untrusted=True,
  )


investigate_incident_container_tool = ToolDefinition(
  name="docker.investigate_incident_container",
  description=(
    "Collect bounded, read-only state, logs, metrics, image metadata, and "
    "recent events for a container from the configured local Docker daemon."
  ),
  input_model=DockerInvestigationCriteria,
  handler=_investigate_incident_container,
  read_only=True,
  persists_evidence=True,
)
