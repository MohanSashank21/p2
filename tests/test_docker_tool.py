from datetime import UTC, datetime
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import pytest

from app.db.user import User
from app.schemas.investigation_schema import (
  DockerInvestigationCriteria,
  IntegrationInvestigationResult,
)
from app.tools.contracts import ToolContext
from app.tools.registry import create_tool_registry


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="docker-tool-test@example.invalid",
      display_name="Docker Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _arguments() -> DockerInvestigationCriteria:
  return DockerInvestigationCriteria(
    source_id=uuid.uuid4(),
    container_id="a" * 64,
    log_tail_lines=25,
  )


def _evidence(
  context: ToolContext,
  arguments: DockerInvestigationCriteria,
  evidence_id: uuid.UUID,
  status: str,
  *,
  logs_truncated: bool = False,
):
  return SimpleNamespace(
    id=evidence_id,
    incident_id=context.incident_id,
    source_event_id=None,
    evidence_type="docker_investigation",
    incident_source_id=arguments.source_id,
    original_content={
      "container_id": arguments.container_id,
      "evidence": {
        "logs": {"content": "bounded, untrusted log output"},
      },
      "findings": [{"code": "container_nonzero_exit"}],
    },
    normalized_content={
      "retrieval_status": status,
      "query_criteria": {
        "container_id": arguments.container_id,
        "log_tail_lines": arguments.log_tail_lines,
      },
      "query_time_range": {"start": "2026-01-01T00:00:00Z"},
      "evidence": {
        "logs": {"truncated": logs_truncated},
      },
      "findings": [{"code": "container_nonzero_exit"}],
      "unavailable": ["stats"] if status == "partial" else [],
      "errors": (
        [{"component": "stats", "detail": "stats unavailable"}]
        if status == "partial"
        else []
      ),
    },
    created_at=datetime.now(UTC),
  )


@pytest.mark.asyncio
async def test_docker_tool_returns_bounded_evidence_and_truncation(monkeypatch):
  context = _context()
  arguments = _arguments()
  evidence_id = uuid.uuid4()
  context.session.scalar = AsyncMock(
    return_value=_evidence(
      context,
      arguments,
      evidence_id,
      "success",
      logs_truncated=True,
    ),
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  investigate = AsyncMock(
    return_value=(
      "success",
      {
        "docker": IntegrationInvestigationResult(
          status="success",
          evidence_id=evidence_id,
        ),
      },
    ),
  )
  monkeypatch.setattr(
    "app.tools.docker.investigate_incident_integrations",
    investigate,
  )

  result = await create_tool_registry().execute(
    "docker.investigate_incident_container",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.truncated is True
  assert result.completeness == "partial"
  assert result.content_is_untrusted is True
  assert result.data is not None
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
  assert call.args[5].docker == arguments


@pytest.mark.asyncio
async def test_docker_tool_preserves_partial_collector_failures(monkeypatch):
  context = _context()
  arguments = _arguments()
  evidence_id = uuid.uuid4()
  context.session.scalar = AsyncMock(
    return_value=_evidence(
      context,
      arguments,
      evidence_id,
      "partial",
    ),
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.docker.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "partial",
        {
          "docker": IntegrationInvestigationResult(
            status="partial",
            evidence_id=evidence_id,
            detail="stats unavailable",
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "docker.investigate_incident_container",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.error is not None
  assert result.error.code == "partial_collection"
  assert result.data is not None
  assert result.data["unavailable"] == ["stats"]
  assert result.data["errors"][0]["detail"] == "stats unavailable"


@pytest.mark.asyncio
async def test_docker_tool_reports_unavailable_without_persisted_evidence(
  monkeypatch,
):
  context = _context()
  arguments = _arguments()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.docker.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "unavailable",
        {
          "docker": IntegrationInvestigationResult(
            status="unavailable",
            detail="Docker source is disabled",
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "docker.investigate_incident_container",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "unavailable"
  assert result.error is not None
  assert result.error.code == "integration_unavailable"
  assert result.error.message == "Docker source is disabled"
  context.session.scalar.assert_not_awaited()
