import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class IncidentCreateRequest(BaseModel):
  environment_id: uuid.UUID | None = None
  incident_type: str = Field(min_length=1, max_length=64)
  title: str = Field(min_length=1, max_length=255)
  description: str | None = Field(default=None, max_length=10000)
  severity: Literal["low", "medium", "high", "critical"] = "medium"

  @field_validator("incident_type", "title")
  @classmethod
  def validate_non_blank(cls, value: str) -> str:
    value = value.strip()
    if not value:
      raise ValueError("Value cannot be blank")
    return value

  @field_validator("description")
  @classmethod
  def normalize_description(cls, value: str | None) -> str | None:
    if value is None:
      return None
    return value.strip() or None


class IncidentStatusUpdateRequest(BaseModel):
  status: Literal["open", "acknowledged", "resolved"]


class IncidentResponse(BaseModel):
  id: uuid.UUID
  project_id: uuid.UUID
  environment_id: uuid.UUID | None
  source_event_id: uuid.UUID | None
  reported_by_user_id: uuid.UUID | None
  source_type: Literal["manual", "generic_webhook"]
  incident_type: str
  title: str
  description: str | None
  severity: Literal["low", "medium", "high", "critical"]
  status: Literal["open", "acknowledged", "resolved"]
  created_at: datetime
  updated_at: datetime
  resolved_at: datetime | None


class IncidentEvidenceResponse(BaseModel):
  id: uuid.UUID
  incident_id: uuid.UUID
  source_event_id: uuid.UUID | None
  evidence_type: Literal["manual_report", "webhook_payload"]
  original_content: dict
  normalized_content: dict
  created_at: datetime
