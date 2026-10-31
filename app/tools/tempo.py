from sqlalchemy import select

from app.db.incident import IncidentEvidence
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  IntegrationInvestigationResult,
)
from app.schemas.source_schema import TraceQueryRequest
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


async def _query_incident_traces(
  context: ToolContext,
  arguments: TraceQueryRequest,
) -> ToolResult:
  _aggregate_status, integrations = await investigate_incident_integrations(
    context.session,
    context.redis,
    context.project_id,
    context.incident_id,
    context.user,
    CombinedIncidentInvestigationRequest(traces=arguments),
  )
  result: IntegrationInvestigationResult = integrations["traces"]
  if result.status == "unavailable":
    return ToolResult(
      status="unavailable",
      error=ToolError(
        code="integration_unavailable",
        message=result.detail or "Tempo could not retrieve incident traces.",
      ),
    )
  if result.status not in {"success", "empty"} or result.evidence_id is None:
    raise RuntimeError("Tempo investigation returned an invalid result")

  evidence: IncidentEvidence | None = await context.session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.id == result.evidence_id,
      IncidentEvidence.incident_id == context.incident_id,
    ),
  )
  if evidence is None:
    raise RuntimeError("Tempo investigation evidence was not persisted")

  normalized = evidence.normalized_content
  trace_count = normalized.get("trace_count")
  span_count = normalized.get("span_count")
  if (
    not isinstance(trace_count, int)
    or isinstance(trace_count, bool)
    or not isinstance(span_count, int)
    or isinstance(span_count, bool)
  ):
    raise RuntimeError("Persisted Tempo evidence has invalid trace counts")
  truncated = arguments.trace_id is None and trace_count >= arguments.limit
  status = "partial" if truncated else result.status
  return ToolResult(
    status=status,
    data={
      "evidence": evidence_payload(evidence),
      "trace_count": trace_count,
      "span_count": span_count,
      "query": normalized.get("query_criteria"),
      "time_range": normalized.get("time_range"),
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
    content_is_untrusted=True,
  )


query_incident_traces_tool = ToolDefinition(
  name="tempo.query_incident_traces",
  description=(
    "Search bounded Tempo traces using an exact trace ID or constrained "
    "service and attribute filters for the authorized incident."
  ),
  input_model=TraceQueryRequest,
  handler=_query_incident_traces,
  read_only=True,
  persists_evidence=True,
)
