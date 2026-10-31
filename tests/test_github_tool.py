from datetime import UTC, datetime
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import pytest

from app.db.user import User
from app.schemas.investigation_schema import (
  GitHubInvestigationCriteria,
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
      email="github-tool-test@example.invalid",
      display_name="GitHub Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _arguments() -> GitHubInvestigationCriteria:
  return GitHubInvestigationCriteria(
    repository_id=1234,
    event_id=uuid.uuid4(),
  )


def _workflow_context(
  *,
  logs_available: bool = True,
  logs_truncated: bool = False,
  code_files_truncated: bool = False,
  code_files_unavailable: list[dict[str, str]] | None = None,
) -> dict:
  return {
    "event_id": "event",
    "repository": "example/service",
    "workflow_run": {"id": 789, "conclusion": "failure"},
    "jobs": [{"name": "tests", "conclusion": "failure"}],
    "commit": {"sha": "a" * 40},
    "code_files": [{"path": "app.py", "content": "untrusted source text"}],
    "code_files_unavailable": code_files_unavailable or [],
    "code_files_truncated": code_files_truncated,
    "commit_history": [],
    "logs": "untrusted workflow output" if logs_available else "",
    "logs_available": logs_available,
    "logs_truncated": logs_truncated,
  }


def _evidence(
  context: ToolContext,
  evidence_id: uuid.UUID,
  workflow_context: dict,
):
  return SimpleNamespace(
    id=evidence_id,
    incident_id=context.incident_id,
    evidence_type="github_context",
    incident_source_id=None,
    original_content={
      "event_id": workflow_context["event_id"],
      "context": workflow_context,
    },
    created_at=datetime.now(UTC),
  )


@pytest.mark.asyncio
async def test_github_tool_returns_workflow_context_as_untrusted_evidence(
  monkeypatch,
):
  context = _context()
  arguments = _arguments()
  evidence_id = uuid.uuid4()
  workflow_context = _workflow_context()
  context.session.scalar = AsyncMock(
    return_value=_evidence(context, evidence_id, workflow_context),
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  investigate = AsyncMock(
    return_value=(
      "success",
      {
        "github": IntegrationInvestigationResult(
          status="success",
          evidence_id=evidence_id,
        ),
      },
    ),
  )
  monkeypatch.setattr(
    "app.tools.github.investigate_incident_integrations",
    investigate,
  )

  result = await create_tool_registry().execute(
    "github.investigate_failed_workflow",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "success"
  assert result.content_is_untrusted is True
  assert result.completeness == "complete"
  assert result.truncated is False
  assert result.data == {
    "context": workflow_context,
    "content_is_untrusted": True,
  }
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
  assert call.args[5].github == arguments


@pytest.mark.asyncio
async def test_github_tool_reports_partial_context_metadata(monkeypatch):
  context = _context()
  arguments = _arguments()
  evidence_id = uuid.uuid4()
  workflow_context = _workflow_context(
    logs_truncated=True,
    code_files_truncated=True,
    code_files_unavailable=[{"path": "large.bin", "reason": "not text"}],
  )
  context.session.scalar = AsyncMock(
    return_value=_evidence(context, evidence_id, workflow_context),
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.github.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "success",
        {
          "github": IntegrationInvestigationResult(
            status="success",
            evidence_id=evidence_id,
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "github.investigate_failed_workflow",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "partial"
  assert result.completeness == "partial"
  assert result.truncated is True
  assert result.error is not None
  assert result.error.code == "partial_collection"
  assert result.evidence[0].id == evidence_id


@pytest.mark.asyncio
async def test_github_tool_returns_explicit_unavailable_result(monkeypatch):
  context = _context()
  arguments = _arguments()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  monkeypatch.setattr(
    "app.tools.github.investigate_incident_integrations",
    AsyncMock(
      return_value=(
        "unavailable",
        {
          "github": IntegrationInvestigationResult(
            status="unavailable",
            detail="GitHub App is not configured",
          ),
        },
      ),
    ),
  )

  result = await create_tool_registry().execute(
    "github.investigate_failed_workflow",
    arguments.model_dump(mode="json"),
    context,
  )

  assert result.status == "unavailable"
  assert result.error is not None
  assert result.error.code == "integration_unavailable"
  assert result.error.message == "GitHub App is not configured"
  context.session.scalar.assert_not_awaited()
