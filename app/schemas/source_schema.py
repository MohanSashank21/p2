import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceCreateRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)
  environment_id: uuid.UUID | None = None
  source_type: Literal["generic_webhook"] = "generic_webhook"

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Source name cannot be blank")
    return name


class SourceResponse(BaseModel):
  id: uuid.UUID
  project_id: uuid.UUID
  environment_id: uuid.UUID | None
  name: str
  source_type: str
  enabled: bool
  created_at: datetime


class SourceCredentialResponse(SourceResponse):
  credential: str


class IncomingSourceEvent(BaseModel):
  model_config = ConfigDict(extra="allow")

  event_id: str | None = Field(default=None, max_length=255)
  event_type: str = Field(default="unknown", min_length=1, max_length=64)
  title: str = Field(min_length=1, max_length=255)
  description: str | None = Field(default=None, max_length=10000)
  severity: Literal["low", "medium", "high", "critical"] = "medium"

  @field_validator("title", "event_type")
  @classmethod
  def validate_non_blank(cls, value: str) -> str:
    value = value.strip()
    if not value:
      raise ValueError("Value cannot be blank")
    return value

class SourceEventResponse(BaseModel):
  id: uuid.UUID
  source_id: uuid.UUID
  project_id: uuid.UUID
  environment_id: uuid.UUID | None
  external_event_id: str | None
  event_type: str
  title: str
  description: str | None
  severity: str
  received_at: datetime
  duplicate: bool = False


class SourceEventDetailResponse(SourceEventResponse):
  original_payload: dict


class SourceEventAcceptedResponse(BaseModel):
  event: SourceEventResponse
  incident_id: uuid.UUID
  duplicate: bool
