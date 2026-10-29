import hashlib
import hmac
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.exceptions import (
  GitHubConflictError,
  GitHubIntegrationError,
  GitHubNotFoundError,
  PermissionDeniedError,
  ProjectNotFoundError,
)
from app.db.database import get_db
from app.db.github import GitHubInstallation, GitHubRepository, GitHubWebhookEvent
from app.db.redis import get_redis
from app.db.user import User
from app.schemas.github_schema import (
  GitHubAvailableRepositoryResponse,
  GitHubHealthResponse,
  GitHubInstallationCompletionRequest,
  GitHubInstallationResponse,
  GitHubRepositoryResponse,
  GitHubSetupUrlResponse,
  GitHubWebhookEventResponse,
  GitHubWebhookResponse,
  GitHubWorkflowInvestigationResponse,
)
from app.services.github_project_service import (
  check_installation_health,
  complete_installation_setup,
  connect_repository,
  create_installation_setup,
  disconnect_installation,
  disconnect_repository,
  get_connected_repository,
  get_workflow_event_investigation,
  list_available_repositories,
  list_connected_repositories,
  list_installations,
  list_webhook_events,
)

router = APIRouter(prefix="/projects/{project_id}/github", tags=["github"])
github_webhook_router = APIRouter(prefix="/webhooks", tags=["github"])
_NON_FAILURE_WORKFLOW_CONCLUSIONS = {"success", "neutral", "skipped", "cancelled"}


def _raise_project_access_error(error: Exception) -> HTTPException:
  if isinstance(error, ProjectNotFoundError):
    return HTTPException(status_code=404, detail=str(error))
  if isinstance(error, PermissionDeniedError):
    return HTTPException(status_code=403, detail=str(error))
  raise error


def _is_actionable_github_event(event_name: str, payload: dict) -> bool:
  if event_name != "workflow_run" or payload.get("action") != "completed":
    return False
  workflow_run = payload.get("workflow_run")
  if not isinstance(workflow_run, dict):
    return False
  conclusion = workflow_run.get("conclusion")
  return (
    not isinstance(conclusion, str)
    or conclusion not in _NON_FAILURE_WORKFLOW_CONCLUSIONS
  )


def _installation_response(installation: GitHubInstallation) -> GitHubInstallationResponse:
  return GitHubInstallationResponse(
    project_id=str(installation.project_id),
    installation_id=installation.installation_id,
    account_id=installation.account_id,
    account_login=installation.account_login,
    status=installation.status,
    created_at=installation.created_at,
  )


async def _repository_response(
  session: AsyncSession,
  repository: GitHubRepository,
) -> GitHubRepositoryResponse:
  installation = await session.get(
    GitHubInstallation,
    repository.installation_id,
  )
  installation_id = installation.installation_id if installation else 0
  return GitHubRepositoryResponse(
    id=repository.github_repo_id,
    project_id=str(repository.project_id),
    installation_id=installation_id,
    full_name=repository.full_name,
    owner=repository.owner,
    default_branch=repository.default_branch,
    html_url=repository.html_url,
    status=repository.status,
    created_at=repository.created_at,
    updated_at=repository.updated_at,
  )


def _webhook_event_response(event: GitHubWebhookEvent) -> GitHubWebhookEventResponse:
  return GitHubWebhookEventResponse(
    id=str(event.id),
    delivery_id=event.delivery_id,
    event_name=event.event_name,
    action=event.action,
    payload=event.payload,
    received_at=event.received_at,
  )


@router.post("/installations/setup", response_model=GitHubSetupUrlResponse)
async def create_setup_url(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
  redis: Redis = Depends(get_redis),
) -> GitHubSetupUrlResponse:
  try:
    url = await create_installation_setup(session, project_id, user, redis)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubIntegrationError as error:
    raise HTTPException(status_code=error.status_code, detail=error.detail) from error
  return GitHubSetupUrlResponse(url=url)


@router.post("/installations/complete", response_model=GitHubInstallationResponse)
async def complete_setup(
  project_id: uuid.UUID,
  request: GitHubInstallationCompletionRequest,
  session: AsyncSession = Depends(get_db),
  redis: Redis = Depends(get_redis),
) -> GitHubInstallationResponse:
  try:
    installation = await complete_installation_setup(
      session,
      redis,
      installation_id=request.installation_id,
      state=request.state,
      setup_action=request.setup_action,
    )
  except GitHubIntegrationError as error:
    raise HTTPException(status_code=error.status_code, detail=error.detail) from error
  return _installation_response(installation)


@router.get("/installations", response_model=list[GitHubInstallationResponse])
async def list_project_installations(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[GitHubInstallationResponse]:
  try:
    installations = await list_installations(session, project_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  return [_installation_response(item) for item in installations]


@router.get(
  "/installations/{installation_id}/repositories",
  response_model=list[GitHubAvailableRepositoryResponse],
)
async def list_installation_repositories(
  project_id: uuid.UUID,
  installation_id: int,
  page: int = 1,
  per_page: int = 20,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[GitHubAvailableRepositoryResponse]:
  try:
    await list_installations(session, project_id, user)
    repositories = await list_available_repositories(
      session,
      project_id,
      installation_id,
      user,
      page=page,
      per_page=per_page,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except GitHubIntegrationError as error:
    raise HTTPException(status_code=error.status_code, detail=error.detail) from error
  return [
    GitHubAvailableRepositoryResponse(
      id=repo.get("id"),
      full_name=repo.get("full_name"),
      private=bool(repo.get("private", False)),
      owner=repo.get("owner", {}).get("login", ""),
      default_branch=repo.get("default_branch"),
      html_url=repo.get("html_url", ""),
    )
    for repo in repositories
  ]


@router.get("/installations/{installation_id}/health", response_model=GitHubHealthResponse)
async def installation_health(
  project_id: uuid.UUID,
  installation_id: int,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> GitHubHealthResponse:
  try:
    result = await check_installation_health(
      session,
      project_id,
      installation_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return GitHubHealthResponse(**result)


@router.get("/repositories", response_model=list[GitHubRepositoryResponse])
async def list_project_repositories(
  project_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[GitHubRepositoryResponse]:
  try:
    repositories = await list_connected_repositories(session, project_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  return [
    await _repository_response(session, item)
    for item in repositories
  ]


@router.post("/installations/{installation_id}/repositories/{repository_id}", response_model=GitHubRepositoryResponse)
async def connect_project_repository(
  project_id: uuid.UUID,
  installation_id: int,
  repository_id: int,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> GitHubRepositoryResponse:
  try:
    repository = await connect_repository(
      session,
      project_id,
      installation_id,
      repository_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubConflictError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except GitHubIntegrationError as error:
    raise HTTPException(status_code=error.status_code, detail=error.detail) from error
  return await _repository_response(session, repository)


@router.get("/repositories/{repository_id}", response_model=GitHubRepositoryResponse)
async def get_project_repository(
  project_id: uuid.UUID,
  repository_id: int,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> GitHubRepositoryResponse:
  try:
    repository = await get_connected_repository(
      session,
      project_id,
      repository_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return await _repository_response(session, repository)


@router.delete("/repositories/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect_project_repository(
  project_id: uuid.UUID,
  repository_id: int,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> Response:
  try:
    await disconnect_repository(session, project_id, repository_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/installations/{installation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect_project_installation(
  project_id: uuid.UUID,
  installation_id: int,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> Response:
  try:
    await disconnect_installation(session, project_id, installation_id, user)
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
  "/repositories/{repository_id}/webhook-events",
  response_model=list[GitHubWebhookEventResponse],
  summary="List received GitHub webhook events",
)
async def list_repository_webhook_events(
  project_id: uuid.UUID,
  repository_id: int,
  page: int = 1,
  per_page: int = 20,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> list[GitHubWebhookEventResponse]:
  try:
    events = await list_webhook_events(
      session,
      project_id,
      repository_id,
      user,
      page=page,
      per_page=per_page,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  return [_webhook_event_response(event) for event in events]


@router.get(
  "/repositories/{repository_id}/webhook-events/{event_id}/investigation",
  response_model=GitHubWorkflowInvestigationResponse,
  summary="Fetch investigation context for a failed workflow run",
)
async def get_repository_workflow_investigation(
  project_id: uuid.UUID,
  repository_id: int,
  event_id: uuid.UUID,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> GitHubWorkflowInvestigationResponse:
  try:
    context = await get_workflow_event_investigation(
      session,
      project_id,
      repository_id,
      event_id,
      user,
    )
  except (ProjectNotFoundError, PermissionDeniedError) as error:
    raise _raise_project_access_error(error) from error
  except GitHubNotFoundError as error:
    raise HTTPException(status_code=404, detail=str(error)) from error
  except GitHubConflictError as error:
    raise HTTPException(status_code=409, detail=str(error)) from error
  except GitHubIntegrationError as error:
    raise HTTPException(status_code=error.status_code, detail=error.detail) from error
  return GitHubWorkflowInvestigationResponse(**context)


@github_webhook_router.post(
  "/github",
  response_model=GitHubWebhookResponse,
  status_code=status.HTTP_202_ACCEPTED,
  summary="Receive GitHub App webhook delivery",
)
async def receive_github_webhook(
  request: Request,
  session: AsyncSession = Depends(get_db),
) -> GitHubWebhookResponse:
  if settings.GITHUB_WEBHOOK_SECRET is None:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="GitHub webhook secret is not configured",
    )

  raw = await request.body()
  signature = request.headers.get("x-hub-signature-256")
  if not signature:
    raise HTTPException(status_code=403, detail="Missing GitHub webhook signature")
  expected = "sha256=" + hmac.new(
    settings.GITHUB_WEBHOOK_SECRET.get_secret_value().encode("utf-8"),
    raw,
    hashlib.sha256,
  ).hexdigest()
  if not hmac.compare_digest(signature, expected):
    raise HTTPException(status_code=403, detail="Invalid GitHub webhook signature")

  try:
    payload = json.loads(raw)
  except json.JSONDecodeError as error:
    raise HTTPException(status_code=400, detail="Request body must be JSON") from error

  if not isinstance(payload, dict):
    raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")

  event_name = request.headers.get("x-github-event") or "unknown"
  if not _is_actionable_github_event(event_name, payload):
    return GitHubWebhookResponse(
      accepted=True,
      duplicate=False,
      stored_count=0,
      ignored_reason="Only completed workflow failures are stored",
    )

  repository = payload.get("repository")
  if not isinstance(repository, dict):
    return GitHubWebhookResponse(accepted=False, duplicate=False, stored_count=0, ignored_reason="No repository metadata found")

  github_repo_id = repository.get("id")
  if not isinstance(github_repo_id, int):
    return GitHubWebhookResponse(accepted=False, duplicate=False, stored_count=0, ignored_reason="Repository metadata was missing")

  repositories = await session.scalars(
    select(GitHubRepository).where(
      GitHubRepository.github_repo_id == github_repo_id,
      GitHubRepository.status == "active",
    ),
  )
  connected_repositories = list(repositories)
  if not connected_repositories:
    return GitHubWebhookResponse(
      accepted=False,
      duplicate=False,
      stored_count=0,
      ignored_reason="No connected repository found for this GitHub repository",
    )

  delivery_id = request.headers.get("x-github-delivery") or str(uuid.uuid4())
  project_ids = [repo.project_id for repo in connected_repositories]
  existing_events = await session.scalars(
    select(GitHubWebhookEvent).where(
      GitHubWebhookEvent.project_id.in_(project_ids),
      GitHubWebhookEvent.delivery_id == delivery_id,
    ),
  )
  existing_project_ids = {event.project_id for event in existing_events}
  new_events = [
    GitHubWebhookEvent(
      project_id=repo.project_id,
      github_repository_id=repo.id,
      delivery_id=delivery_id,
      event_name=event_name,
      action=(
        str(payload.get("action"))
        if payload.get("action") is not None
        else None
      ),
      payload=payload,
    )
    for repo in connected_repositories
    if repo.project_id not in existing_project_ids
  ]
  if not new_events:
    return GitHubWebhookResponse(accepted=True, duplicate=True, stored_count=0)

  session.add_all(new_events)
  await session.commit()
  return GitHubWebhookResponse(
    accepted=True,
    duplicate=False,
    stored_count=len(new_events),
  )
