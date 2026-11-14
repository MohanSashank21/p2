import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


_CREDENTIAL_ASSIGNMENT = re.compile(
  r"(?i)\b(?:api[_-]?key|access[_-]?token|password|passwd|secret|"
  r"authorization)\s*[:=]\s*\S+",
)
_BEARER_CREDENTIAL = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")


class InternetSearchRequest(BaseModel):
  model_config = ConfigDict(extra="forbid")

  query: str = Field(min_length=3, max_length=512)

  @field_validator("query")
  @classmethod
  def validate_query(cls, query: str) -> str:
    normalized = query.strip()
    if len(normalized) < 3:
      raise ValueError("Search query must contain at least 3 non-whitespace characters.")
    if _CREDENTIAL_ASSIGNMENT.search(normalized) or _BEARER_CREDENTIAL.search(normalized):
      raise ValueError("Search query must not contain credentials or secret values.")
    return normalized
