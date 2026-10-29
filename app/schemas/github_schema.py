from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class GitHubSetupUrlResponse(BaseModel):
  url: str


class GitHubInstallationResponse(BaseModel):
  project_id: str
  installation_id: int
  account_id: int | None
  account_login: str
  status: str
  created_at: datetime


class GitHubRepositoryResponse(BaseModel):
  id: int
  project_id: str
  installation_id: int
  full_name: str
  owner: str
  default_branch: str | None
  html_url: str
  status: str
  created_at: datetime
  updated_at: datetime


class GitHubAvailableRepositoryResponse(BaseModel):
  id: int
  full_name: str
  private: bool = False
  owner: str
  default_branch: str | None = None
  html_url: str


class GitHubHealthResponse(BaseModel):
  healthy: bool
  installation_id: int
  repository_accessible: bool


class GitHubDataResponse(BaseModel):
  data: dict[str, Any]


class GitHubListResponse(BaseModel):
  data: list[dict[str, Any]]


class GitHubFileResponse(BaseModel):
  path: str
  sha: str
  size: int
  content: str
  html_url: str | None = None


class GitHubWorkflowLogsResponse(BaseModel):
  available: bool
  downloaded: bool


class GitHubWebhookEventResponse(BaseModel):
  id: str
  delivery_id: str
  event_name: str
  action: str | None
  payload: dict[str, Any]
  received_at: datetime


class GitHubWorkflowInvestigationResponse(BaseModel):
  event_id: str
  repository: str
  workflow_run: dict[str, Any]
  jobs: list[dict[str, Any]]
  commit: dict[str, Any]
  code_files: list[dict[str, Any]]
  code_files_unavailable: list[dict[str, str]]
  code_files_truncated: bool
  commit_history: list[dict[str, Any]]
  logs: str | None
  logs_available: bool
  logs_truncated: bool


class GitHubWebhookResponse(BaseModel):
  accepted: bool
  duplicate: bool = False
  stored_count: int = 0
  ignored_reason: str | None = None


class GitHubInstallationCompletionRequest(BaseModel):
  installation_id: int
  state: str = Field(min_length=1, max_length=256)
  setup_action: str = Field(default="install", min_length=1, max_length=32)


class GitHubEvidenceRequest(BaseModel):
  evidence_type: str = Field(min_length=1, max_length=64)
  metadata: dict[str, Any]
