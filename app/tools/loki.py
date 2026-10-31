from sqlalchemy import select

from app.db.incident import IncidentEvidence
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  IntegrationInvestigationResult,
)
from app.schemas.source_schema import LokiQueryRequest
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


async def _query_incident_logs(
  context: ToolContext,
  arguments: LokiQueryRequest,
) -> ToolResult:
  _aggregate_status, integrations = await investigate_incident_integrations(
    context.session,
    context.redis,
    context.project_id,
    context.incident_id,
    context.user,
    CombinedIncidentInvestigationRequest(loki=arguments),
  )
  result: IntegrationInvestigationResult = integrations["loki"]
  if result.status == "unavailable":
    return ToolResult(
      status="unavailable",
      error=ToolError(
        code="integration_unavailable",
        message=result.detail or "Loki could not retrieve incident logs.",
      ),
    )
  if result.status not in {"success", "empty"} or result.evidence_id is None:
    raise RuntimeError("Loki investigation returned an invalid result")

  evidence: IncidentEvidence | None = await context.session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.id == result.evidence_id,
      IncidentEvidence.incident_id == context.incident_id,
    ),
  )
  if evidence is None:
    raise RuntimeError("Loki investigation evidence was not persisted")

  entry_count = evidence.normalized_content.get("entry_count")
  if not isinstance(entry_count, int):
    raise RuntimeError("Persisted Loki evidence has no valid entry count")
  truncated = entry_count >= arguments.limit
  status = "partial" if truncated else result.status
  return ToolResult(
    status=status,
    data={
      "evidence": evidence_payload(evidence),
      "entry_count": entry_count,
      "query": evidence.normalized_content.get("query"),
      "time_range": evidence.normalized_content.get("time_range"),
    },
    evidence=[
      ToolEvidenceRef(
        id=evidence.id,
        evidence_type=evidence.evidence_type,
        source_id=evidence.incident_source_id,
        observed_at=evidence.created_at,
      ),
    ],
    completeness="partial" if truncated else "complete",
    truncated=truncated,
  )


query_incident_logs_tool = ToolDefinition(
  name="loki.query_incident_logs",
  description=(
    "Query bounded Loki logs correlated with labels already recorded on "
    "the authorized incident."
  ),
  input_model=LokiQueryRequest,
  handler=_query_incident_logs,
  read_only=True,
)
