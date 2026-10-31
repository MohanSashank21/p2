import uuid
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
  ]
  evidence_id: uuid.UUID | None = None
  detail: str | None = None


class CombinedIncidentInvestigationResponse(BaseModel):
  status: Literal["success", "partial", "unavailable"]
  incident_id: uuid.UUID
  integrations: dict[str, IntegrationInvestigationResult]
  evidence: list[IncidentEvidenceResponse]
