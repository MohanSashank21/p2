import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ProjectCreateRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)
  description: str | None = Field(default=None, max_length=4000)
  manager_user_id: uuid.UUID

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Project name cannot be blank")
    return name

  @field_validator("description")
  @classmethod
  def normalize_description(cls, description: str | None) -> str | None:
    if description is None:
      return None
    return description.strip()

class ProjectWorkerInvitationRequest(BaseModel):
  user_id: uuid.UUID

class ProjectResponse(BaseModel):
  id: uuid.UUID
  organisation_id: uuid.UUID
  name: str
  description: str | None
  role: Literal["owner", "manager", "worker"]

class ProjectMembershipResponse(BaseModel):
  id: uuid.UUID
  project_id: uuid.UUID
  user_id: uuid.UUID
  role: Literal["manager", "worker"]

class ProjectInvitationResponse(BaseModel):
  message: str
  expires_in: int

class ProjectInvitationAcceptRequest(BaseModel):
  token: str = Field(min_length=32, max_length=200)
