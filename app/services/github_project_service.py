from __future__ import annotations

import json
import secrets
import uuid
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  GitHubConflictError,
  GitHubIntegrationError,
  GitHubNotFoundError,
  PermissionDeniedError,
)
from app.db.github import (
  GitHubInstallation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.project_membership import ProjectMembership
from app.db.user import User
from app.services import github_service
from app.services.project_service import get_accessible_project

_MAX_INVESTIGATION_CODE_FILES = 10


async def _require_owner(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> None:
  _project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can manage GitHub")


async def create_installation_setup(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  redis,
) -> str:
  await _require_owner(session, project_id, user)
  if not settings.GITHUB_APP_SLUG:
    raise GitHubIntegrationError(503, "GitHub App slug is not configured")
  state = secrets.token_urlsafe(32)
  state_value = json.dumps(
    {"project_id": str(project_id), "user_id": str(user.id)},
    separators=(",", ":"),
  )
  stored = await redis.set(
    f"github:install-state:{state}",
    state_value,
    ex=600,
    nx=True,
  )
  if not stored:
    raise GitHubIntegrationError(503, "Could not create GitHub setup state")
  return (
    f"https://github.com/apps/{settings.GITHUB_APP_SLUG}/installations/new?"
    f"{urlencode({'state': state})}"
  )


async def complete_installation_setup(
  session: AsyncSession,
  redis,
  *,
  installation_id: int,
  state: str,
  setup_action: str,
) -> GitHubInstallation:
  import json

  if setup_action not in {"install", "update"}:
    raise GitHubIntegrationError(400, "GitHub installation setup was cancelled")
  if not state or len(state) > 256:
    raise GitHubIntegrationError(400, "Invalid GitHub installation state")
  state_key = f"github:install-state:{state}"
  state_value = await redis.get(state_key)
  if not isinstance(state_value, str):
    raise GitHubIntegrationError(400, "GitHub installation state expired")
  try:
    state_data = json.loads(state_value)
    project_id = uuid.UUID(state_data["project_id"])
    user_id = uuid.UUID(state_data["user_id"])
  except (KeyError, TypeError, ValueError) as error:
    raise GitHubIntegrationError(400, "Invalid GitHub installation state") from error

  membership = await session.scalar(
    select(ProjectMembership).where(
      ProjectMembership.project_id == project_id,
      ProjectMembership.user_id == user_id,
      ProjectMembership.role == "owner",
    ),
  )
  if membership is None:
    raise GitHubIntegrationError(403, "Project owner access has changed")

  details = await github_service.get_installation_details(installation_id)
  account = details.get("account")
  if not isinstance(account, dict):
    raise GitHubIntegrationError(502, "GitHub returned invalid installation details")
  account_login = account.get("login")
  account_id = account.get("id")
  if not isinstance(account_login, str) or not isinstance(account_id, int):
    raise GitHubIntegrationError(502, "GitHub returned invalid installation account")

  consumed_state = await redis.getdel(state_key)
  if consumed_state != state_value:
    raise GitHubIntegrationError(400, "GitHub installation state was already used")

  installation = await session.scalar(
    select(GitHubInstallation).where(
      GitHubInstallation.project_id == project_id,
      GitHubInstallation.installation_id == installation_id,
    ),
  )
  if installation is None:
    installation = GitHubInstallation(
      project_id=project_id,
      installation_id=installation_id,
      account_id=account_id,
      account_login=account_login,
      status="active",
    )
    session.add(installation)
  else:
    installation.account_id = account_id
    installation.account_login = account_login
    installation.status = "active"
  await session.commit()
  await session.refresh(installation)
  return installation


async def list_installations(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> list[GitHubInstallation]:
  await get_accessible_project(session, project_id, user)
  result = await session.scalars(
    select(GitHubInstallation)
    .where(GitHubInstallation.project_id == project_id)
    .order_by(GitHubInstallation.created_at, GitHubInstallation.id),
  )
  return list(result)


async def get_project_installation(
  session: AsyncSession,
  project_id: uuid.UUID,
  installation_id: int,
  user: User,
) -> GitHubInstallation:
  await get_accessible_project(session, project_id, user)
  installation = await session.scalar(
    select(GitHubInstallation).where(
      GitHubInstallation.project_id == project_id,
      GitHubInstallation.installation_id == installation_id,
      GitHubInstallation.status == "active",
    ),
  )
  if installation is None:
    raise GitHubNotFoundError("GitHub installation not found")
  return installation


async def list_available_repositories(
  session: AsyncSession,
  project_id: uuid.UUID,
  installation_id: int,
  user: User,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  installation = await get_project_installation(
    session,
    project_id,
    installation_id,
    user,
  )
  token = await github_service.create_installation_token(
    installation.installation_id,
  )
  return await github_service.list_installation_repositories(
    token,
    page=page,
    per_page=per_page,
  )


async def connect_repository(
  session: AsyncSession,
  project_id: uuid.UUID,
  installation_id: int,
  repository_id: int,
  user: User,
) -> GitHubRepository:
  await _require_owner(session, project_id, user)
  installation = await get_project_installation(
    session,
    project_id,
    installation_id,
    user,
  )
  token = await github_service.create_installation_token(
    installation.installation_id,
  )
  repository = await github_service.get_repository_by_id(token, repository_id)
  owner = repository.get("owner")
  if not isinstance(owner, dict):
    raise GitHubIntegrationError(502, "GitHub returned invalid repository metadata")
  full_name = repository.get("full_name")
  owner_login = owner.get("login")
  repo_id = repository.get("id")
  html_url = repository.get("html_url")
  if (
    not isinstance(repo_id, int)
    or repo_id != repository_id
    or not isinstance(owner_login, str)
    or not isinstance(full_name, str)
    or not isinstance(html_url, str)
  ):
    raise GitHubIntegrationError(502, "GitHub returned invalid repository metadata")

  existing = await session.scalar(
    select(GitHubRepository).where(
      GitHubRepository.project_id == project_id,
      GitHubRepository.github_repo_id == repo_id,
    ),
  )
  if existing is not None and existing.status == "active":
    raise GitHubConflictError("Repository is already connected to this project")
  if existing is not None:
    existing.installation_id = installation.id
    existing.full_name = full_name
    existing.owner = owner_login
    existing.default_branch = repository.get("default_branch")
    existing.html_url = html_url
    existing.status = "active"
    github_repository = existing
  else:
    github_repository = GitHubRepository(
      project_id=project_id,
      installation_id=installation.id,
      github_repo_id=repo_id,
      full_name=full_name,
      owner=owner_login,
      default_branch=repository.get("default_branch"),
      html_url=html_url,
      status="active",
    )
    session.add(github_repository)
  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise GitHubConflictError(
      "Repository is already connected to this project",
    ) from error
  await session.refresh(github_repository)
  return github_repository


async def list_connected_repositories(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> list[GitHubRepository]:
  await get_accessible_project(session, project_id, user)
  result = await session.scalars(
    select(GitHubRepository)
    .where(
      GitHubRepository.project_id == project_id,
      GitHubRepository.status == "active",
    )
    .order_by(GitHubRepository.full_name, GitHubRepository.github_repo_id),
  )
  return list(result)


async def get_connected_repository(
  session: AsyncSession,
  project_id: uuid.UUID,
  repository_id: int,
  user: User,
) -> GitHubRepository:
  await get_accessible_project(session, project_id, user)
  repository = await session.scalar(
    select(GitHubRepository)
    .where(
      GitHubRepository.project_id == project_id,
      GitHubRepository.github_repo_id == repository_id,
      GitHubRepository.status == "active",
    ),
  )
  if repository is None:
    raise GitHubNotFoundError("Connected GitHub repository not found")
  return repository

async def refresh_repository_metadata(
  session: AsyncSession,
  repository: GitHubRepository,
) -> GitHubRepository:
  installation = await session.get(GitHubInstallation, repository.installation_id)
  if installation is None or installation.status != "active":
    raise GitHubNotFoundError("GitHub installation is disconnected")
  token = await github_service.create_installation_token(installation.installation_id)
  details = await github_service.get_repository_by_id(
    token,
    repository.github_repo_id,
  )
  owner = details.get("owner")
  if not isinstance(owner, dict):
    raise GitHubIntegrationError(502, "GitHub returned invalid repository metadata")
  full_name = details.get("full_name")
  owner_login = owner.get("login")
  html_url = details.get("html_url")
  if (
    not isinstance(full_name, str)
    or not isinstance(owner_login, str)
    or not isinstance(html_url, str)
  ):
    raise GitHubIntegrationError(502, "GitHub returned invalid repository metadata")
  repository.full_name = full_name
  repository.owner = owner_login
  repository.default_branch = details.get("default_branch")
  repository.html_url = html_url
  await session.commit()
  await session.refresh(repository)
  return repository

async def disconnect_repository(
  session: AsyncSession,
  project_id: uuid.UUID,
  repository_id: int,
  user: User,
) -> None:
  await _require_owner(session, project_id, user)
  repository = await get_connected_repository(
    session,
    project_id,
    repository_id,
    user,
  )
  repository.status = "disconnected"
  await session.commit()

async def disconnect_installation(
  session: AsyncSession,
  project_id: uuid.UUID,
  installation_id: int,
  user: User,
) -> None:
  await _require_owner(session, project_id, user)
  installation = await get_project_installation(
    session,
    project_id,
    installation_id,
    user,
  )
  installation.status = "disconnected"
  repositories = await session.scalars(
    select(GitHubRepository).where(
      GitHubRepository.installation_id == installation.id,
      GitHubRepository.status == "active",
    ),
  )
  for repository in repositories:
    repository.status = "disconnected"
  await session.commit()


async def github_client_for_repository(
  session: AsyncSession,
  repository: GitHubRepository,
) -> github_service.GitHubClient:
  installation = await session.get(GitHubInstallation, repository.installation_id)
  if installation is None or installation.status != "active":
    raise GitHubNotFoundError("GitHub installation is disconnected")
  token = await github_service.create_installation_token(installation.installation_id)
  return github_service.GitHubClient(token)


async def connected_repository_for_api(
  session: AsyncSession,
  project_id: uuid.UUID,
  repository_id: int,
  user: User,
) -> tuple[GitHubRepository, github_service.GitHubClient]:
  repository = await get_connected_repository(
    session,
    project_id,
    repository_id,
    user,
  )
  repository = await refresh_repository_metadata(session, repository)
  return repository, await github_client_for_repository(session, repository)


async def check_installation_health(
  session: AsyncSession,
  project_id: uuid.UUID,
  installation_id: int,
  user: User,
) -> dict[str, Any]:
  installation = await get_project_installation(
    session,
    project_id,
    installation_id,
    user,
  )
  token = await github_service.create_installation_token(installation.installation_id)
  repositories = await github_service.list_installation_repositories(
    token,
    page=1,
    per_page=1,
  )
  return {
    "healthy": True,
    "installation_id": installation.installation_id,
    "repository_accessible": bool(repositories) or installation.status == "active",
  }


async def list_webhook_events(
  session: AsyncSession,
  project_id: uuid.UUID,
  repository_id: int,
  user: User,
  *,
  page: int,
  per_page: int,
):
  repository = await get_connected_repository(
    session,
    project_id,
    repository_id,
    user,
  )
  from app.db.github import GitHubWebhookEvent

  result = await session.scalars(
    select(GitHubWebhookEvent)
    .where(GitHubWebhookEvent.github_repository_id == repository.id)
    .order_by(GitHubWebhookEvent.received_at.desc(), GitHubWebhookEvent.id)
    .offset((page - 1) * per_page)
    .limit(per_page),
  )
  return list(result)


async def get_workflow_event_investigation(
  session: AsyncSession,
  project_id: uuid.UUID,
  repository_id: int,
  event_id: uuid.UUID,
  user: User,
) -> dict[str, Any]:
  repository = await get_connected_repository(
    session,
    project_id,
    repository_id,
    user,
  )
  event = await session.scalar(
    select(GitHubWebhookEvent).where(
      GitHubWebhookEvent.id == event_id,
      GitHubWebhookEvent.github_repository_id == repository.id,
    ),
  )
  if event is None:
    raise GitHubNotFoundError("GitHub webhook event not found")

  workflow_run = event.payload.get("workflow_run")
  if (
    event.event_name != "workflow_run"
    or event.action != "completed"
    or not isinstance(workflow_run, dict)
  ):
    raise GitHubConflictError(
      "Investigation context is available only for completed workflow runs",
    )
  conclusion = workflow_run.get("conclusion")
  if isinstance(conclusion, str) and conclusion in {
    "success",
    "neutral",
    "skipped",
    "cancelled",
  }:
    raise GitHubConflictError(
      "Investigation context is available only for failed or unexpected runs",
    )

  run_id = workflow_run.get("id")
  head_sha = workflow_run.get("head_sha")
  if (
    isinstance(run_id, bool)
    or not isinstance(run_id, int)
    or run_id <= 0
    or not isinstance(head_sha, str)
    or not head_sha
  ):
    raise GitHubIntegrationError(
      502,
      "Stored workflow event is missing its run ID or commit SHA",
    )

  installation = await session.get(GitHubInstallation, repository.installation_id)
  if installation is None or installation.status != "active":
    raise GitHubNotFoundError("GitHub installation is disconnected")
  token = await github_service.create_installation_token(
    installation.installation_id,
  )
  run_details = await github_service.get_workflow_run(
    token,
    repository.full_name,
    run_id,
  )
  jobs = await github_service.get_workflow_jobs(
    token,
    repository.full_name,
    run_id,
    page=1,
    per_page=100,
  )
  commit = await github_service.get_commit(
    token,
    repository.full_name,
    head_sha,
  )
  changed_files = commit.get("files", [])
  if not isinstance(changed_files, list):
    raise GitHubIntegrationError(
      502,
      "GitHub returned invalid changed-file details",
    )
  code_files: list[dict[str, Any]] = []
  code_files_unavailable: list[dict[str, str]] = []
  for item in changed_files[:_MAX_INVESTIGATION_CODE_FILES]:
    if not isinstance(item, dict):
      continue
    path = item.get("filename")
    if not isinstance(path, str) or item.get("status") == "removed":
      continue
    if not isinstance(item.get("patch"), str):
      code_files_unavailable.append(
        {"path": path, "reason": "GitHub did not provide a text diff for this file"},
      )
      continue
    try:
      code_files.append(
        await github_service.get_file(
          token,
          repository.full_name,
          path,
          head_sha,
        ),
      )
    except GitHubIntegrationError as error:
      if error.status_code not in {413, 415}:
        raise
      code_files_unavailable.append(
        {"path": path, "reason": error.detail},
      )
  commit_history = await github_service.get_commits(
    token,
    repository.full_name,
    page=1,
    per_page=10,
    ref=head_sha,
  )
  logs = await github_service.get_workflow_run_logs(
    token,
    repository.full_name,
    run_id,
  )
  return {
    "event_id": str(event.id),
    "repository": repository.full_name,
    "workflow_run": run_details,
    "jobs": jobs,
    "commit": commit,
    "code_files": code_files,
    "code_files_unavailable": code_files_unavailable,
    "code_files_truncated": len(changed_files) > _MAX_INVESTIGATION_CODE_FILES,
    "commit_history": commit_history,
    "logs": logs["logs"],
    "logs_available": logs["available"],
    "logs_truncated": logs["truncated"],
  }
