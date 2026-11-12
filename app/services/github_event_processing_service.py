from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.github import (
  GitHubIncidentCorrelation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.incident import Incident, IncidentEvidence

_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")


class InvalidGitHubWorkflowEvent(ValueError):
  pass


def _positive_id(value: Any) -> str | None:
  if isinstance(value, int) and not isinstance(value, bool) and value > 0:
    normalized = str(value)
    return normalized if len(normalized) <= 32 else None
  if (
    isinstance(value, str)
    and value.isascii()
    and len(value) <= 32
    and value.isdigit()
  ):
    number = int(value)
    return str(number) if number > 0 else None
  return None


def _bounded_text(value: Any, limit: int) -> str | None:
  if not isinstance(value, str):
    return None
  printable = "".join(character for character in value if character.isprintable())
  normalized = " ".join(printable.split())
  return normalized[:limit] or None


def _event_metadata(
  event: GitHubWebhookEvent,
  repository: GitHubRepository,
) -> tuple[str, str | None, str | None, str | None]:
  payload = event.payload
  if not isinstance(payload, dict):
    raise InvalidGitHubWorkflowEvent("invalid_payload")
  repository_data = payload.get("repository")
  workflow_run = payload.get("workflow_run")
  if not isinstance(repository_data, dict) or not isinstance(workflow_run, dict):
    raise InvalidGitHubWorkflowEvent("missing_workflow_data")

  repository_id = repository_data.get("id")
  if (
    not isinstance(repository_id, int)
    or isinstance(repository_id, bool)
    or repository_id != repository.github_repo_id
  ):
    raise InvalidGitHubWorkflowEvent("repository_mismatch")
  if event.event_name != "workflow_run" or event.action != "completed":
    raise InvalidGitHubWorkflowEvent("unexpected_event")

  workflow_run_id = _positive_id(workflow_run.get("id"))
  if workflow_run_id is None:
    raise InvalidGitHubWorkflowEvent("missing_workflow_run_id")

  raw_sha = workflow_run.get("head_sha")
  commit_sha = (
    raw_sha.lower()
    if isinstance(raw_sha, str) and _COMMIT_SHA.fullmatch(raw_sha)
    else None
  )
  conclusion = _bounded_text(workflow_run.get("conclusion"), 64) or "unknown"
  workflow_name = (
    _bounded_text(workflow_run.get("name"), 180)
    or _bounded_text(workflow_run.get("display_title"), 180)
    or f"workflow run {workflow_run_id}"
  )
  title = f"GitHub workflow failed: {workflow_name}"[:255]
  return workflow_run_id, commit_sha, conclusion, title


async def process_github_workflow_event(
  session: AsyncSession,
  event_id: uuid.UUID,
) -> uuid.UUID | None:
  event = await session.scalar(
    select(GitHubWebhookEvent)
    .where(GitHubWebhookEvent.id == event_id)
    .with_for_update(),
  )
  if event is None:
    return None
  if event.processing_status == "processed":
    return event.incident_id
  if event.processing_status != "processing":
    return None

  repository = await session.scalar(
    select(GitHubRepository).where(
      GitHubRepository.id == event.github_repository_id,
      GitHubRepository.project_id == event.project_id,
    ),
  )
  if repository is None:
    raise InvalidGitHubWorkflowEvent("repository_not_found")

  workflow_run_id, commit_sha, conclusion, title = _event_metadata(
    event,
    repository,
  )
  event.workflow_run_id = workflow_run_id
  event.commit_sha = commit_sha

  identifiers = [("workflow_run", workflow_run_id)]
  if commit_sha is not None:
    identifiers.append(("commit", commit_sha))
  exact_identifier_filter = or_(
    *(
      and_(
        GitHubIncidentCorrelation.identifier_type == identifier_type,
        GitHubIncidentCorrelation.identifier_value == identifier_value,
      )
      for identifier_type, identifier_value in identifiers
    ),
  )
  existing_correlations = list(
    await session.scalars(
      select(GitHubIncidentCorrelation).where(
        GitHubIncidentCorrelation.project_id == event.project_id,
        GitHubIncidentCorrelation.github_repository_id
        == event.github_repository_id,
        exact_identifier_filter,
      ),
    ),
  )
  matching_incident_ids = {
    correlation.incident_id for correlation in existing_correlations
  }

  if len(matching_incident_ids) == 1:
    incident_id = next(iter(matching_incident_ids))
    incident = await session.scalar(
      select(Incident).where(
        Incident.id == incident_id,
        Incident.project_id == event.project_id,
      ),
    )
    if incident is None:
      raise RuntimeError("GitHub incident correlation points to a missing incident")
    for identifier_type, identifier_value in identifiers:
      if not any(
        item.identifier_type == identifier_type
        and item.identifier_value == identifier_value
        for item in existing_correlations
      ):
        session.add(
          GitHubIncidentCorrelation(
            project_id=event.project_id,
            github_repository_id=event.github_repository_id,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            incident_id=incident.id,
          ),
        )
  else:
    incident = Incident(
      project_id=event.project_id,
      source_type="github",
      incident_type="github_workflow_failure",
      title=title,
      description=(
        f"Repository: {repository.full_name}\n"
        f"Workflow run: {workflow_run_id}\n"
        f"Conclusion: {conclusion}"
        + (f"\nCommit: {commit_sha}" if commit_sha is not None else "")
      ),
      severity="medium",
      status="open",
    )
    session.add(incident)
    await session.flush()

    if not matching_incident_ids:
      for identifier_type, identifier_value in identifiers:
        if not any(
          item.identifier_type == identifier_type
          and item.identifier_value == identifier_value
          for item in existing_correlations
        ):
          session.add(
            GitHubIncidentCorrelation(
              project_id=event.project_id,
              github_repository_id=event.github_repository_id,
              identifier_type=identifier_type,
              identifier_value=identifier_value,
              incident_id=incident.id,
            ),
          )

  event.incident_id = incident.id
  event.processing_status = "processed"
  event.available_at = None
  event.lease_expires_at = None
  event.last_failure_code = None
  event.processed_at = datetime.now(UTC)
  session.add(
    IncidentEvidence(
      incident_id=incident.id,
      evidence_type="github_workflow_event",
      original_content={
        "event_id": str(event.id),
        "delivery_id": event.delivery_id,
        "repository": {
          "id": repository.github_repo_id,
          "full_name": repository.full_name,
        },
        "workflow_run": {
          "id": workflow_run_id,
          "name": _bounded_text(event.payload["workflow_run"].get("name"), 180),
          "conclusion": conclusion,
          "head_sha": commit_sha,
          "created_at": _bounded_text(
            event.payload["workflow_run"].get("created_at"),
            64,
          ),
          "run_started_at": _bounded_text(
            event.payload["workflow_run"].get("run_started_at"),
            64,
          ),
          "updated_at": _bounded_text(
            event.payload["workflow_run"].get("updated_at"),
            64,
          ),
          "completed_at": _bounded_text(
            event.payload["workflow_run"].get("completed_at"),
            64,
          ),
        },
      },
      normalized_content={
        "source": "github",
        "event_id": str(event.id),
        "repository_id": repository.github_repo_id,
        "repository": repository.full_name,
        "workflow_run_id": workflow_run_id,
        "commit_sha": commit_sha,
        "workflow_run": {
          "id": workflow_run_id,
          "conclusion": conclusion,
          "created_at": _bounded_text(
            event.payload["workflow_run"].get("created_at"),
            64,
          ),
          "run_started_at": _bounded_text(
            event.payload["workflow_run"].get("run_started_at"),
            64,
          ),
          "updated_at": _bounded_text(
            event.payload["workflow_run"].get("updated_at"),
            64,
          ),
          "completed_at": _bounded_text(
            event.payload["workflow_run"].get("completed_at"),
            64,
          ),
        },
        "commit": {"sha": commit_sha} if commit_sha is not None else {},
        "received_at": event.received_at.isoformat(),
      },
    ),
  )
  await session.flush()
  return incident.id
