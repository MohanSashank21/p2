import uuid
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.incident_schema import IncidentEvidenceResponse
from app.schemas.prometheus_schema import (
  PrometheusInstantQueryRequest,
  PrometheusRangeQueryRequest,
)
from app.schemas.source_schema import LokiQueryRequest, TraceQueryRequest


class DockerInvestigationCriteria(BaseModel):
  source_id: uuid.UUID
  container_id: str = Field(min_length=12, max_length=64)
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


class GitHubInvestigationCriteria(BaseModel):
  repository_id: int = Field(gt=0)
  event_id: uuid.UUID


class CombinedIncidentInvestigationRequest(BaseModel):
  traces: TraceQueryRequest | None = None
  loki: LokiQueryRequest | None = None
  docker: DockerInvestigationCriteria | None = None
  github: GitHubInvestigationCriteria | None = None
  prometheus: (
    PrometheusInstantQueryRequest | PrometheusRangeQueryRequest | None
  ) = None

  @model_validator(mode="after")
  def require_an_integration(self) -> Self:
    if not any(
      (
        self.traces,
        self.loki,
        self.docker,
        self.github,
        self.prometheus,
      )
    ):
      raise ValueError("Request at least one integration to investigate")
    return self


class IntegrationInvestigationResult(BaseModel):
  status: Literal[
    "success",
    "empty",
    "partial",
    "unavailable",
    "included",
    "not_configured",
    "not_requested",
  ]
  evidence_id: uuid.UUID | None = None
  detail: str | None = None


class CombinedIncidentInvestigationResponse(BaseModel):
  status: Literal["success", "partial", "unavailable"]
  incident_id: uuid.UUID
  integrations: dict[str, IntegrationInvestigationResult]
  evidence: list[IncidentEvidenceResponse]


class InvestigationRunResponse(BaseModel):
  id: uuid.UUID
  project_id: uuid.UUID
  incident_id: uuid.UUID
  requested_by_user_id: uuid.UUID | None
  requested_integrations: list[str]
  request_criteria: dict
  status: Literal["running", "succeeded", "partial", "failed", "cancelled"]
  aggregate_status: Literal["success", "partial", "unavailable"] | None
  integrations: dict[str, IntegrationInvestigationResult] | None
  evidence_ids: list[uuid.UUID]
  failure_code: str | None
  failure_detail: str | None
  attempt_count: int
  synthesis_status: Literal["not_started", "running", "succeeded", "failed"]
  synthesis_report: dict | None
  synthesis_model: str | None
  synthesis_prompt_version: str | None
  synthesis_schema_version: str | None
  synthesis_input_tokens: int | None
  synthesis_output_tokens: int | None
  synthesis_provider_attempts: int | None
  synthesis_attempt_count: int
  synthesis_failure_code: str | None
  synthesis_completed_at: datetime | None
  created_at: datetime
  started_at: datetime
  completed_at: datetime | None
