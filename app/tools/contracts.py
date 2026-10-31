from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Generic, Literal, TypeVar
import uuid

from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.user import User

ToolStatus = Literal["success", "empty", "partial", "unavailable", "error"]
ToolCompleteness = Literal["complete", "partial", "unknown"]
InputT = TypeVar("InputT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class ToolContext:
  session: AsyncSession
  redis: Redis
  project_id: uuid.UUID
  incident_id: uuid.UUID
  user: User


class ToolError(BaseModel):
  code: str = Field(min_length=1, max_length=64)
  message: str = Field(min_length=1, max_length=500)


class ToolEvidenceRef(BaseModel):
  id: uuid.UUID
  evidence_type: str
  source_id: uuid.UUID | None = None
  observed_at: datetime


class ToolResult(BaseModel):
  status: ToolStatus
  data: dict[str, Any] | None = None
  error: ToolError | None = None
  evidence: list[ToolEvidenceRef] = Field(default_factory=list)
  collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
  completeness: ToolCompleteness = "unknown"
  truncated: bool = False
  content_is_untrusted: bool = Field(
    default=False,
    description="True when returned provider or persisted evidence content is untrusted input.",
  )


class ToolDescriptor(BaseModel):
  name: str
  description: str
  input_schema: dict[str, Any]
  read_only: bool = Field(
    description=(
      "True when the tool performs no provider-side mutations; it may still "
      "persist evidence when persists_evidence is true."
    ),
  )
  persists_evidence: bool = Field(
    description="True when successful investigation results may be persisted as incident evidence.",
  )


class ToolNotFoundError(LookupError):
  pass


@dataclass(frozen=True, slots=True)
class ToolDefinition(Generic[InputT]):
  """An internal tool; read_only excludes provider mutations, not evidence writes."""

  name: str
  description: str
  input_model: type[InputT]
  handler: Callable[[ToolContext, InputT], Awaitable[ToolResult]]
  read_only: bool = True
  persists_evidence: bool = False
