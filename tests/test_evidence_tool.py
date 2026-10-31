from datetime import UTC, datetime
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import sqlite

from app.db.user import User
from app.services import incident_service
from app.tools.contracts import ToolContext
from app.tools.evidence import IncidentEvidenceCriteria
from app.tools.registry import create_tool_registry


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="evidence-tool-test@example.invalid",
      display_name="Evidence Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _evidence(
  context: ToolContext,
  evidence_type: str,
) -> SimpleNamespace:
  return SimpleNamespace(
    id=uuid.uuid4(),
    incident_id=context.incident_id,
    source_event_id=None,
    evidence_type=evidence_type,
    incident_source_id=None,
    original_content={"message": "untrusted provider payload"},
    normalized_content={"summary": "recorded evidence"},
    created_at=datetime.now(UTC),
  )


@pytest.mark.asyncio
async def test_evidence_tool_returns_paginated_project_scoped_evidence(
  monkeypatch,
):
  context = _context()
  arguments = IncidentEvidenceCriteria(
    limit=2,
    offset=4,
    evidence_types=["grafana_notification", "loki_logs"],
  )
  items = [
    _evidence(context, "grafana_notification"),
    _evidence(context, "loki_logs"),
    _evidence(context, "loki_logs"),
  ]
  read_evidence = AsyncMock(return_value=items)
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.incident_evidence.list_incident_evidence",
    read_evidence,
  )

  result = await create_tool_registry().execute(
    "incident.read_evidence",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.truncated is True
  assert result.completeness == "partial"
  assert result.content_is_untrusted is True
  assert result.data is not None
  assert result.data["returned_count"] == 2
  assert result.data["has_more"] is True
  assert result.data["next_offset"] == 6
  assert result.data["content_is_untrusted"] is True
  assert [item.evidence_type for item in result.evidence] == [
    "grafana_notification",
    "loki_logs",
  ]
  read_evidence.assert_awaited_once_with(
    context.session,
    context.project_id,
    context.incident_id,
    context.user,
    limit=3,
    offset=4,
    evidence_types={"grafana_notification", "loki_logs"},
  )


@pytest.mark.asyncio
async def test_evidence_tool_reports_empty_page(monkeypatch):
  context = _context()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.incident_evidence.list_incident_evidence",
    AsyncMock(return_value=[]),
  )

  result = await create_tool_registry().execute(
    "incident.read_evidence",
    IncidentEvidenceCriteria().model_dump(mode="json"),
    context,
  )

  assert result.status == "empty"
  assert result.completeness == "complete"
  assert result.truncated is False
  assert result.data is not None
  assert result.data["evidence"] == []
  assert result.evidence == []


@pytest.mark.asyncio
async def test_evidence_tool_rejects_invalid_paging_and_filter_values(
  monkeypatch,
):
  context = _context()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.incident_evidence.list_incident_evidence",
    AsyncMock(return_value=[]),
  )

  result = await create_tool_registry().execute(
    "incident.read_evidence",
    {"limit": 1000, "offset": -1, "evidence_types": ["unknown"]},
    context,
  )

  assert result.status == "error"
  assert result.error is not None
  assert result.error.code == "invalid_arguments"


@pytest.mark.asyncio
async def test_existing_evidence_service_applies_filter_and_page_bounds(
  monkeypatch,
):
  context = _context()
  evidence = _evidence(context, "loki_logs")
  session = AsyncMock()
  session.scalars.return_value = [evidence]
  authorization_check = AsyncMock()
  monkeypatch.setattr(
    incident_service,
    "get_project_incident",
    authorization_check,
  )

  result = await incident_service.list_incident_evidence(
    session,
    context.project_id,
    context.incident_id,
    context.user,
    limit=11,
    offset=20,
    evidence_types={"loki_logs", "trace_spans"},
  )

  assert result == [evidence]
  authorization_check.assert_awaited_once_with(
    session,
    context.project_id,
    context.incident_id,
    context.user,
  )
  statement = session.scalars.await_args.args[0]
  compiled = statement.compile(
    dialect=sqlite.dialect(),
    compile_kwargs={"render_postcompile": True},
  )
  assert "incident_evidence.evidence_type IN" in str(compiled)
  assert "LIMIT" in str(compiled)
  assert "OFFSET" in str(compiled)
  assert {11, 20, "loki_logs", "trace_spans"} <= set(compiled.params.values())
