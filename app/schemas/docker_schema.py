import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class DockerConnectionResponse(BaseModel):
  status: Literal["connected"]
  daemon_version: str
  api_version: str | None = None


class DockerContainerSummary(BaseModel):
  container_id: str
  name: str
  image: str
  state: str
  status: str
  created_at: str | None = None


class DockerContainerListResponse(BaseModel):
  containers: list[DockerContainerSummary]
  limit: int
  truncated: bool


class DockerInvestigationRequest(BaseModel):
  source_id: uuid.UUID
  container_id: str = Field(min_length=12, max_length=64)
  incident_id: uuid.UUID | None = None
  log_tail_lines: int = Field(default=100, ge=1, le=500)

  @field_validator("container_id")
  @classmethod
  def validate_container_id(cls, container_id: str) -> str:
    normalized = container_id.strip().lower()
    if (
      len(normalized) < 12
      or len(normalized) > 64
      or any(character not in "0123456789abcdef" for character in normalized)
    ):
      raise ValueError("container_id must be a 12-64 character hexadecimal ID")
    return normalized


class DockerInvestigationResponse(BaseModel):
  status: Literal["success", "partial", "unavailable"]
  source_id: uuid.UUID
  project_id: uuid.UUID
  container_id: str
  collected_at: datetime
  query_criteria: dict[str, Any]
  query_time_range: dict[str, datetime]
  evidence: dict[str, Any] | None = None
  unavailable: list[str] = Field(default_factory=list)
  errors: list[dict[str, str]] = Field(default_factory=list)
  findings: list[dict[str, Any]] = Field(default_factory=list)
  incident_evidence_id: uuid.UUID | None = None
