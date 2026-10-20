import uuid
from typing import Literal
from pydantic import BaseModel, Field, field_validator

class OrganisationCreateRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Organisation name cannot be blank")
    return name

class OrganisationResponse(BaseModel):
  id: uuid.UUID
  name: str
  owner_user_id: uuid.UUID
  role: Literal["owner", "member"]
