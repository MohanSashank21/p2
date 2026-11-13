from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PermissionDeniedError
from app.db.incident import Incident, IncidentEvidence
from app.db.investigation_run import InvestigationRun
from app.db.user import User
from app.services.incident_service import get_project_incident, list_incident_evidence
from app.services.investigation_graph import (
  InvestigationBudget,
  InvestigationEvidence,
  InvestigationGraphState,
  InvestigationModel,
  ReadOnlyToolBinding,
  ReadOnlyToolResult,
  compile_investigation_graph,
  create_investigation_state,
  investigation_graph_config,
  resume_investigation_graph,
)
from app.services.investigation_run_service import (
  RUN_TIMEOUT_SECONDS,
  complete_agent_investigation_run,
)
from app.services.investigation_synthesis_service import _sanitize_evidence
from app.tools.contracts import ToolContext, ToolDefinition, ToolResult
from app.tools.registry import ToolRegistry

MAX_INITIAL_EVIDENCE = 100


def _persisted_evidence_view(
  evidence: IncidentEvidence,
) -> InvestigationEvidence:
  return InvestigationEvidence(
    id=evidence.id,
    evidence_type=evidence.evidence_type,
    provenance=(
      f"incident_evidence:{evidence.id};"
      f"incident:{evidence.incident_id};"
      f"persisted_at:{evidence.created_at.isoformat()}"
    ),
    content={
      "persisted_at": evidence.created_at.isoformat(),
      "content_is_untrusted": True,
      "normalized_content": _sanitize_evidence(evidence.normalized_content),
    },
  )


async def _load_tool_evidence(
  context: ToolContext,
  result: ToolResult,
) -> list[InvestigationEvidence]:
  if not result.evidence:
    return []
  identifiers = {item.id for item in result.evidence}
  if len(identifiers) != len(result.evidence):
    raise RuntimeError("Read-only tool returned duplicate evidence references.")
  rows = await context.session.scalars(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_id == context.incident_id,
      IncidentEvidence.id.in_(identifiers),
    ),
  )
  evidence_by_id = {
    item.id: item
    for item in rows
    if item.incident_id == context.incident_id
  }
  if evidence_by_id.keys() != identifiers:
    raise RuntimeError(
      "Read-only tool referenced evidence not persisted for this incident.",
    )
  return [
    _persisted_evidence_view(evidence_by_id[item.id])
    for item in result.evidence
  ]


def create_registry_bindings(
  registry: ToolRegistry,
  context: ToolContext,
) -> list[ReadOnlyToolBinding]:
  bindings: list[ReadOnlyToolBinding] = []
  for definition in registry.get_tool_definitions():
    if not definition.read_only:
      raise ValueError(f"Investigation tool {definition.name!r} is not read-only.")
    bindings.append(_bind_definition(registry, context, definition))
  return bindings


def _bind_definition(
  registry: ToolRegistry,
  context: ToolContext,
  definition: ToolDefinition[Any],
) -> ReadOnlyToolBinding:
  async def execute(arguments: dict[str, Any]) -> ReadOnlyToolResult:
    result = await registry.execute(definition.name, arguments, context)
    if not isinstance(result, ToolResult):
      raise RuntimeError("Read-only registry returned an invalid tool result.")
    evidence = await _load_tool_evidence(context, result)
    return ReadOnlyToolResult(
      status=result.status,
      evidence=evidence,
      error_code=result.error.code if result.error is not None else None,
    )

  return ReadOnlyToolBinding(
    name=definition.name,
    description=definition.description,
    input_model=definition.input_model,
    handler=execute,
    read_only=definition.read_only,
  )


async def run_agent_investigation(
  *,
  session: AsyncSession,
  redis: Redis,
  run: InvestigationRun,
  user: User,
  question: str,
  registry: ToolRegistry,
  model: InvestigationModel,
  checkpointer: BaseCheckpointSaver,
  budget: InvestigationBudget,
) -> tuple[InvestigationRun, InvestigationGraphState]:
  if run.status != "running":
    raise ValueError("Only a running InvestigationRun can execute the graph.")
  if run.project_id is None or run.incident_id is None:
    raise ValueError("InvestigationRun must have project and incident scope.")
  if run.requested_by_user_id != user.id:
    raise PermissionDeniedError("InvestigationRun belongs to another user.")
  if budget.max_duration_seconds > RUN_TIMEOUT_SECONDS:
    raise ValueError(
      f"Investigation duration cannot exceed {RUN_TIMEOUT_SECONDS} seconds.",
    )
  normalized_question = question.strip()
  expected_request = {
    "mode": "bounded_ai_investigation",
    "question": normalized_question,
    "budget": budget.model_dump(mode="json"),
  }
  if (
    run.requested_integrations != ["investigation_graph"]
    or run.request_criteria != expected_request
  ):
    raise ValueError("InvestigationRun request does not match the graph input.")
  started_at = run.started_at
  if started_at.tzinfo is None:
    started_at = started_at.replace(tzinfo=UTC)
  deadline_epoch_seconds = started_at.timestamp() + budget.max_duration_seconds

  incident: Incident = await get_project_incident(
    session,
    run.project_id,
    run.incident_id,
    user,
  )
  persisted_evidence = await list_incident_evidence(
    session,
    run.project_id,
    run.incident_id,
    user,
    limit=MAX_INITIAL_EVIDENCE + 1,
  )
  evidence_truncated = len(persisted_evidence) > MAX_INITIAL_EVIDENCE
  evidence = [
    _persisted_evidence_view(item)
    for item in persisted_evidence[:MAX_INITIAL_EVIDENCE]
  ]
  tool_context = ToolContext(
    session=session,
    redis=redis,
    project_id=run.project_id,
    incident_id=run.incident_id,
    user=user,
  )
  bindings: Sequence[ReadOnlyToolBinding] = create_registry_bindings(
    registry,
    tool_context,
  )
  state = create_investigation_state(
    run_id=run.id,
    incident_id=incident.id,
    question=normalized_question,
    evidence=evidence,
    tools=bindings,
    budget=budget,
    initial_evidence_truncated=evidence_truncated,
    deadline_epoch_seconds=deadline_epoch_seconds,
  )
  graph = compile_investigation_graph(
    model=model,
    tools=bindings,
    budget=budget,
    checkpointer=checkpointer,
  )
  config = investigation_graph_config(run.id)
  checkpoint = await graph.aget_state(config)
  if checkpoint.values:
    if not checkpoint.next and checkpoint.values.get("terminal"):
      result = checkpoint.values
    elif checkpoint.next:
      result = await resume_investigation_graph(graph, run.id)
    else:
      raise RuntimeError("Investigation checkpoint has no resumable graph node.")
  else:
    result = await graph.ainvoke(state, config)
  completed_run = await complete_agent_investigation_run(
    session,
    run.id,
    result,
  )
  return completed_run, result
