import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ProjectCreateRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)
  description: str | None = Field(default=None, max_length=4000)

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


class ProjectUpdateRequest(BaseModel):
  name: str | None = Field(default=None, min_length=1, max_length=120)
  description: str | None = Field(default=None, max_length=4000)

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str | None) -> str | None:
    if name is None:
      return None
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


class ProjectResponse(BaseModel):
  id: uuid.UUID
  name: str
  description: str | None
  role: Literal["owner", "member"]


class ProjectMembershipSummary(BaseModel):
  id: uuid.UUID
  name: str
  role: Literal["owner", "member"]
