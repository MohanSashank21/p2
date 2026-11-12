from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvestigationFinding(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  kind: Literal[
    "observation",
    "hypothesis",
    "conclusion",
    "alternative",
    "recommendation",
  ]
  claim: str = Field(min_length=1, max_length=1000)
  evidence_ids: list[str] = Field(min_length=1, max_length=8)
  confidence: Literal["low", "moderate", "high"]

  @model_validator(mode="after")
  def require_unique_evidence_ids(self) -> InvestigationFinding:
    if len(set(self.evidence_ids)) != len(self.evidence_ids):
      raise ValueError("evidence_ids must not contain duplicates")
    return self


class InvestigationSynthesisReport(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  status: Literal["conclusion", "inconclusive"]
  findings: list[InvestigationFinding] = Field(min_length=1, max_length=12)
  data_gaps: list[str] = Field(max_length=8)
  next_steps: list[str] = Field(max_length=8)

  @model_validator(mode="after")
  def validate_conclusion_status(self) -> InvestigationSynthesisReport:
    has_conclusion = any(
      finding.kind == "conclusion"
      for finding in self.findings
    )
    if has_conclusion != (self.status == "conclusion"):
      raise ValueError(
        "conclusion status must match the presence of a conclusion finding",
      )
    return self


class InvestigationSynthesisResult(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  model: str
  report: InvestigationSynthesisReport
  provider_attempts: int = Field(default=1, ge=1)
  input_tokens: int | None = Field(default=None, ge=0)
  output_tokens: int | None = Field(default=None, ge=0)


class InvestigationSynthesisRunResponse(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  run_id: uuid.UUID
  incident_id: uuid.UUID
  status: Literal["not_started", "running", "succeeded", "failed"]
  report: InvestigationSynthesisReport | None
  model: str | None
  prompt_version: str | None
  schema_version: str | None
  input_tokens: int | None
  output_tokens: int | None
  provider_attempts: int | None
  attempt_count: int
  failure_code: str | None
  completed_at: datetime | None


class UnsupportedEvidenceCitationError(ValueError):
  def __init__(self, evidence_ids: set[str]) -> None:
    self.evidence_ids = evidence_ids
    super().__init__(
      "Synthesis cited evidence IDs not present in the supplied context: "
      + ", ".join(sorted(evidence_ids)),
    )


def validate_evidence_citations(
  report: InvestigationSynthesisReport,
  available_evidence_ids: set[str],
) -> None:
  cited_ids = {
    evidence_id
    for finding in report.findings
    for evidence_id in finding.evidence_ids
  }
  unsupported_ids = cited_ids - available_evidence_ids
  if unsupported_ids:
    raise UnsupportedEvidenceCitationError(unsupported_ids)
