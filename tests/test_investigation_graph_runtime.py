from __future__ import annotations

from contextlib import asynccontextmanager
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import BaseModel
from redis.asyncio import Redis

from app.core.exceptions import PermissionDeniedError
from app.db.user import User
from app.services.investigation_graph_runtime import (
  _load_tool_evidence,
  _persisted_evidence_view,
  create_registry_bindings,
  run_agent_investigation,
)
from app.services.investigation_graph import (
  InvestigationBudget,
  InvestigationDecision,
  InvestigationModelResponse,
)
from app.services.investigation_run_service import (
  IdempotencyKeyConflictError,
  reserve_agent_investigation_run,
)
from app.services.investigation_checkpointer import (
  open_postgres_investigation_checkpointer,
  postgres_checkpoint_connection_string,
)
from app.tools.contracts import (
  ToolContext,
  ToolDefinition,
  ToolEvidenceRef,
  ToolResult,
)
from app.tools.registry import ToolRegistry


class QueryArguments(BaseModel):
  query: str


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(spec=Redis),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="graph-runtime@example.invalid",
      display_name="Graph Runtime",
      password_hash="not-a-real-password-hash",
    ),
  )


def _persisted_row(
  *,
  evidence_id: uuid.UUID | None = None,
  incident_id: uuid.UUID | None = None,
) -> SimpleNamespace:
  return SimpleNamespace(
    id=evidence_id or uuid.uuid4(),
    incident_id=incident_id or uuid.uuid4(),
    evidence_type="loki_logs",
    created_at=datetime(2026, 11, 13, tzinfo=UTC),
    normalized_content={
      "line": "Authorization: Bearer abcdefghijklmnop",
      "api_key": "do-not-send",
      "message": "database timeout",
    },
  )


class ScriptedAbstentionModel:
  def __init__(self) -> None:
    self.calls = 0

  def count_input_tokens(self, payload: dict) -> int:
    return len(json.dumps(payload))

  async def propose(
    self,
    _payload: dict,
    *,
    max_output_tokens: int,
  ) -> InvestigationModelResponse:
    self.calls += 1
    return InvestigationModelResponse(
      decision=InvestigationDecision(action="inconclusive"),
      input_tokens=self.count_input_tokens(_payload),
      output_tokens=min(1, max_output_tokens),
    )


def test_persisted_evidence_view_uses_server_ids_and_redacts_secrets():
  row = _persisted_row()

  evidence = _persisted_evidence_view(row)

  assert evidence.id == row.id
  assert str(row.incident_id) in evidence.provenance
  assert evidence.content["content_is_untrusted"] is True
  assert evidence.content["normalized_content"] == {
    "line": "Authorization: [REDACTED]",
    "api_key": "[REDACTED]",
    "message": "database timeout",
  }


@pytest.mark.asyncio
async def test_registry_binding_loads_only_server_persisted_incident_evidence(
  monkeypatch: pytest.MonkeyPatch,
):
  context = _context()
  evidence_row = _persisted_row(incident_id=context.incident_id)
  context.session.scalars.return_value = [evidence_row]
  registry_authorization = AsyncMock()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    registry_authorization,
  )
  arguments_seen = []

  async def query_logs(
    tool_context: ToolContext,
    arguments: QueryArguments,
  ) -> ToolResult:
    arguments_seen.append((tool_context, arguments.query))
    return ToolResult(
      status="success",
      data={"evidence": [{"id": str(uuid.uuid4()), "content": "untrusted"}]},
      evidence=[
        ToolEvidenceRef(
          id=evidence_row.id,
          evidence_type="loki_logs",
          observed_at=evidence_row.created_at,
        ),
      ],
      content_is_untrusted=True,
    )

  registry = ToolRegistry((
    ToolDefinition(
      name="loki.query_incident_logs",
      description="Query incident logs.",
      input_model=QueryArguments,
      handler=query_logs,
      read_only=True,
      persists_evidence=True,
    ),
  ))
  bindings = create_registry_bindings(registry, context)

  result = await bindings[0].handler({"query": "database timeout"})

  assert result.status == "success"
  assert [item.id for item in result.evidence] == [evidence_row.id]
  assert result.evidence[0].content["normalized_content"]["api_key"] == "[REDACTED]"
  assert arguments_seen == [(context, "database timeout")]
  registry_authorization.assert_awaited_once_with(
    context.session,
    context.project_id,
    context.incident_id,
    context.user,
  )
  context.session.scalars.assert_awaited_once()


@pytest.mark.asyncio
async def test_registry_binding_rejects_cross_incident_evidence_references(
  monkeypatch: pytest.MonkeyPatch,
):
  context = _context()
  other_incident_row = _persisted_row()
  context.session.scalars.return_value = [other_incident_row]
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )

  async def query_logs(
    _tool_context: ToolContext,
    _arguments: QueryArguments,
  ) -> ToolResult:
    return ToolResult(
      status="success",
      evidence=[
        ToolEvidenceRef(
          id=other_incident_row.id,
          evidence_type="loki_logs",
          observed_at=other_incident_row.created_at,
        ),
      ],
    )

  registry = ToolRegistry((
    ToolDefinition(
      name="loki.query_incident_logs",
      description="Query incident logs.",
      input_model=QueryArguments,
      handler=query_logs,
      read_only=True,
      persists_evidence=True,
    ),
  ))
  binding = create_registry_bindings(registry, context)[0]

  with pytest.raises(RuntimeError, match="not persisted for this incident"):
    await binding.handler({"query": "database timeout"})


def test_persisted_evidence_view_ignores_provider_supplied_provenance_fields():
  row = _persisted_row()
  row.normalized_content["provenance"] = "provider://spoofed"
  row.normalized_content["id"] = str(uuid.uuid4())

  evidence = _persisted_evidence_view(row)

  assert evidence.id == row.id
  assert evidence.provenance.startswith(f"incident_evidence:{row.id};")
  assert evidence.id != uuid.UUID(row.normalized_content["id"])


@pytest.mark.asyncio
async def test_runtime_connects_registry_graph_and_investigation_run(
  monkeypatch: pytest.MonkeyPatch,
):
  context = _context()
  run_id = uuid.uuid4()
  budget = InvestigationBudget(
    max_cycles=2,
    max_model_calls=2,
    max_model_tokens=2000,
    max_tool_calls=1,
    max_duration_seconds=10,
    max_step_seconds=1,
    max_output_tokens_per_call=100,
  )
  run = SimpleNamespace(
    id=run_id,
    project_id=context.project_id,
    incident_id=context.incident_id,
    requested_by_user_id=context.user.id,
    request_criteria={
      "mode": "bounded_ai_investigation",
      "question": "Investigate the synthetic incident.",
      "budget": budget.model_dump(mode="json"),
    },
    requested_integrations=["investigation_graph"],
    started_at=datetime.now(UTC),
    status="running",
    aggregate_status=None,
    integration_results=None,
    agent_report=None,
    evidence_ids=[],
    failure_code=None,
    failure_detail=None,
    completed_at=None,
  )
  session = context.session
  session.get.return_value = run
  monkeypatch.setattr(
    "app.services.investigation_graph_runtime.get_project_incident",
    AsyncMock(return_value=SimpleNamespace(
      id=context.incident_id,
      project_id=context.project_id,
    )),
  )
  monkeypatch.setattr(
    "app.services.investigation_graph_runtime.list_incident_evidence",
    AsyncMock(return_value=[]),
  )
  model = ScriptedAbstentionModel()

  completed_run, graph_result = await run_agent_investigation(
    session=session,
    redis=context.redis,
    run=run,
    user=context.user,
    question="Investigate the synthetic incident.",
    registry=ToolRegistry(),
    model=model,
    checkpointer=InMemorySaver(),
    budget=budget,
  )

  assert completed_run is run
  assert graph_result["outcome"] == "inconclusive"
  assert run.status == "partial"
  assert run.aggregate_status == "partial"
  assert run.agent_report["outcome"] == "inconclusive"
  assert run.agent_report["budget_usage"]["model_calls"] == 1
  usage = run.agent_report["budget_usage"]
  assert usage["model_tokens"] == (
    usage["model_tokens_consumed"] + usage["model_tokens_reserved"]
  )
  assert usage["model_tokens_consumed"] > 0
  assert usage["model_tokens_reserved"] == 0
  assert run.integration_results is None
  assert model.calls == 1
  session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_runtime_rejects_run_from_another_user_before_model_call():
  context = _context()
  run = SimpleNamespace(
    id=uuid.uuid4(),
    project_id=context.project_id,
    incident_id=context.incident_id,
    requested_by_user_id=uuid.uuid4(),
    request_criteria={},
    status="running",
  )
  model = ScriptedAbstentionModel()
  budget = InvestigationBudget(
    max_cycles=1,
    max_model_calls=1,
    max_model_tokens=100,
    max_tool_calls=0,
    max_duration_seconds=10,
    max_step_seconds=1,
    max_output_tokens_per_call=10,
  )

  with pytest.raises(PermissionDeniedError):
    await run_agent_investigation(
      session=context.session,
      redis=context.redis,
      run=run,
      user=context.user,
      question="Investigate the synthetic incident.",
      registry=ToolRegistry(),
      model=model,
      checkpointer=InMemorySaver(),
      budget=budget,
    )
  assert model.calls == 0


@pytest.mark.asyncio
async def test_agent_run_reservation_is_idempotent_and_request_bound():
  context = _context()
  session = AsyncMock()
  session.add = Mock()
  session.execute.return_value = SimpleNamespace(rowcount=0)
  budget = InvestigationBudget(
    max_cycles=2,
    max_model_calls=2,
    max_model_tokens=2000,
    max_tool_calls=1,
    max_duration_seconds=10,
    max_step_seconds=1,
    max_output_tokens_per_call=100,
  )
  existing_run = SimpleNamespace(request_hash="")
  session.scalar.side_effect = [None, existing_run, existing_run]

  async def refresh(run: SimpleNamespace) -> None:
    run.id = uuid.uuid4()

  session.refresh.side_effect = refresh
  run, created = await reserve_agent_investigation_run(
    session,
    context.project_id,
    context.incident_id,
    context.user,
    "  Investigate this incident.  ",
    budget,
    "request-1",
  )
  existing_run.request_hash = run.request_hash

  replay, replay_created = await reserve_agent_investigation_run(
    session,
    context.project_id,
    context.incident_id,
    context.user,
    "Investigate this incident.",
    budget,
    "request-1",
  )

  assert created is True
  assert replay_created is False
  assert replay is existing_run
  assert run.request_criteria["question"] == "Investigate this incident."
  assert run.requested_integrations == ["investigation_graph"]

  with pytest.raises(IdempotencyKeyConflictError):
    await reserve_agent_investigation_run(
      session,
      context.project_id,
      context.incident_id,
      context.user,
      "A different question.",
      budget,
      "request-1",
    )


def test_postgres_checkpoint_connection_url_preserves_url_encoding():
  connection_string = postgres_checkpoint_connection_string(
    "postgresql+asyncpg://agent:pass%40word@db.example.test:5432/opspilot",
  )

  assert connection_string == (
    "postgresql://agent:pass%40word@db.example.test:5432/opspilot"
  )


def test_postgres_checkpoint_rejects_non_postgresql_database_urls():
  with pytest.raises(ValueError, match="require PostgreSQL"):
    postgres_checkpoint_connection_string("sqlite+aiosqlite://")


@pytest.mark.asyncio
async def test_postgres_checkpointer_initializes_and_runs_setup(
  monkeypatch: pytest.MonkeyPatch,
):
  from app.services import investigation_checkpointer

  saver = SimpleNamespace(setup=AsyncMock())
  connection_strings = []

  @asynccontextmanager
  async def saver_context(connection_string: str):
    connection_strings.append(connection_string)
    yield saver

  class FakeSaverFactory:
    @staticmethod
    def from_conn_string(connection_string: str):
      return saver_context(connection_string)

  monkeypatch.setattr(
    investigation_checkpointer,
    "AsyncPostgresSaver",
    FakeSaverFactory,
  )

  async with open_postgres_investigation_checkpointer(
    "postgresql+asyncpg://agent:synthetic-secret@db.example.test/opspilot",
  ) as opened_saver:
    assert opened_saver is saver

  saver.setup.assert_awaited_once()
  assert connection_strings == [
    "postgresql://agent:synthetic-secret@db.example.test/opspilot",
  ]
