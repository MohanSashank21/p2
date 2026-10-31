from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import pytest

from app.db.user import User
from app.schemas.investigation_schema import IntegrationInvestigationResult
from app.schemas.source_schema import TraceQueryRequest
from app.tools.contracts import ToolContext
from app.tools.registry import create_tool_registry


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="tempo-tool-test@example.invalid",
      display_name="Tempo Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _arguments() -> TraceQueryRequest:
  now = datetime.now(UTC)
  return TraceQueryRequest(
    source_id=uuid.uuid4(),
    service_name="checkout-api",
    start=now - timedelta(minutes=5),
    end=now,
    limit=2,
  )


@pytest.mark.asyncio
async def test_tempo_tool_returns_evidence_and_marks_search_limit_as_truncated(
  monkeypatch,
):
  context = _context()
  arguments = _arguments()
  evidence_id = uuid.uuid4()
  evidence = SimpleNamespace(
    id=evidence_id,
    incident_id=context.incident_id,
    source_event_id=None,
    evidence_type="trace_spans",
    incident_source_id=arguments.source_id,
    original_content={"query": {"service_name": "checkout-api"}, "traces": []},
    normalized_content={
      "trace_count": 2,
      "span_count": 4,
      "query_criteria": {"service_name": "checkout-api"},
      "time_range": {
        "start": arguments.start.isoformat(),
        "end": arguments.end.isoformat(),
      },
    },
    created_at=datetime.now(UTC),
  )
  context.session.scalar = AsyncMock(return_value=evidence)
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  investigate = AsyncMock(
    return_value=(
      "success",
      {
        "traces": IntegrationInvestigationResult(
          status="success",
          evidence_id=evidence_id,
        ),
      },
    ),
  )
  monkeypatch.setattr(
    "app.tools.tempo.investigate_incident_integrations",
    investigate,
  )

  result = await create_tool_registry().execute(
    "tempo.query_incident_traces",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.truncated is True
  assert result.completeness == "partial"
  assert result.data is not None
  assert result.data["trace_count"] == 2
  assert result.data["span_count"] == 4
  assert result.data["evidence"]["id"] == str(evidence_id)
  assert result.evidence[0].id == evidence_id
  call = investigate.await_args
  assert call is not None
  assert call.args[:5] == (
    context.session,
    context.redis,
    context.project_id,
    context.incident_id,
    context.user,
  )
  assert call.args[5].traces == arguments


@pytest.mark.asyncio
async def test_tempo_trace_id_query_is_not_marked_truncated_at_one_result(
  monkeypatch,
):
  context = _context()
  arguments = TraceQueryRequest(
    **{
      **_arguments().model_dump(),
      "trace_id": "a" * 32,
      "service_name": None,
      "limit": 1,
    },
  )
  evidence_id = uuid.uuid4()
  context.session.scalar = AsyncMock(
    return_value=SimpleNamespace(
      id=evidence_id,
      incident_id=context.incident_id,
      source_event_id=None,
      evidence_type="trace_spans",
      incident_source_id=arguments.source_id,
      original_content={"query": {}, "traces": []},
      normalized_content={
        "trace_count": 1,
        "span_count": 1,
        "query_criteria": {"trace_id": arguments.trace_id},
        "time_range": {},
      },
      created_at=datetime.now(UTC),
    ),
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.tempo.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "success",
        {
          "traces": IntegrationInvestigationResult(
            status="success",
            evidence_id=evidence_id,
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "tempo.query_incident_traces",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "success"
  assert result.truncated is False
  assert result.completeness == "complete"


@pytest.mark.asyncio
async def test_tempo_tool_returns_structured_unavailable_result(monkeypatch):
  context = _context()
  arguments = _arguments()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.tempo.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "unavailable",
        {
          "traces": IntegrationInvestigationResult(
            status="unavailable",
            detail="Tempo query timed out",
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "tempo.query_incident_traces",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "unavailable"
  assert result.error is not None
  assert result.error.code == "integration_unavailable"
  assert result.error.message == "Tempo query timed out"
  context.session.scalar.assert_not_awaited()
