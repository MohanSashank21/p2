from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import pytest

from app.db.user import User
from app.schemas.investigation_schema import IntegrationInvestigationResult
from app.schemas.source_schema import LokiQueryRequest
from app.tools.contracts import ToolContext
from app.tools.registry import create_tool_registry


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="loki-tool-test@example.invalid",
      display_name="Loki Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _arguments(context: ToolContext) -> LokiQueryRequest:
  now = datetime.now(UTC)
  return LokiQueryRequest(
    source_id=uuid.uuid4(),
    start=now - timedelta(minutes=5),
    end=now,
    labels={"service": "api"},
    limit=1,
  )


@pytest.mark.asyncio
async def test_loki_tool_returns_evidence_and_marks_limit_as_truncated(
  monkeypatch,
):
  context = _context()
  arguments = _arguments(context)
  evidence_id = uuid.uuid4()
  evidence = SimpleNamespace(
    id=evidence_id,
    incident_id=context.incident_id,
    source_event_id=None,
    evidence_type="loki_logs",
    incident_source_id=arguments.source_id,
    original_content={
      "entries": [
        {
          "timestamp": "2026-01-01T00:00:00Z",
          "line": "request failed",
          "labels": {"service": "api"},
        },
      ],
    },
    normalized_content={
      "entry_count": 1,
      "query": '{service="api"}',
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
        "loki": IntegrationInvestigationResult(
          status="success",
          evidence_id=evidence_id,
        ),
      },
    ),
  )
  monkeypatch.setattr(
    "app.tools.loki.investigate_incident_integrations",
    investigate,
  )

  result = await create_tool_registry().execute(
    "loki.query_incident_logs",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.truncated is True
  assert result.completeness == "partial"
  assert result.data is not None
  assert result.data["entry_count"] == 1
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
  assert call.args[5].loki == arguments


@pytest.mark.asyncio
async def test_loki_tool_returns_structured_unavailable_result(monkeypatch):
  context = _context()
  arguments = _arguments(context)
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.loki.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "unavailable",
        {
          "loki": IntegrationInvestigationResult(
            status="unavailable",
            detail="Loki query timed out",
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "loki.query_incident_logs",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "unavailable"
  assert result.error is not None
  assert result.error.code == "integration_unavailable"
  assert result.error.message == "Loki query timed out"
  context.session.scalar.assert_not_awaited()
