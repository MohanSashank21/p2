from datetime import datetime
import math
import uuid
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PrometheusQueryBase(BaseModel):
  model_config = ConfigDict(extra="forbid")

  source_id: uuid.UUID
  expression: str = Field(min_length=1, max_length=8192)
  timeout_seconds: int | None = Field(default=None, ge=1, le=60)
  series_limit: int | None = Field(default=None, ge=1, le=1000)

  @field_validator("expression")
  @classmethod
  def validate_expression(cls, expression: str) -> str:
    expression = expression.strip()
    if not expression:
      raise ValueError("PromQL expression cannot be blank")
    return expression


class PrometheusInstantQueryRequest(PrometheusQueryBase):
  evaluation_time: datetime | None = None

  @field_validator("evaluation_time")
  @classmethod
  def validate_evaluation_time(
    cls,
    evaluation_time: datetime | None,
  ) -> datetime | None:
    if evaluation_time is not None and evaluation_time.utcoffset() is None:
      raise ValueError("Evaluation time must include a timezone")
    return evaluation_time


class PrometheusRangeQueryRequest(PrometheusQueryBase):
  start: datetime
  end: datetime
  step_seconds: float = Field(gt=0)

  @field_validator("start", "end")
  @classmethod
  def validate_timestamp_timezone(cls, value: datetime) -> datetime:
    if value.utcoffset() is None:
      raise ValueError("Query timestamps must include a timezone")
    return value

  @field_validator("step_seconds")
  @classmethod
  def validate_step_is_finite(cls, step_seconds: float) -> float:
    if not math.isfinite(step_seconds):
      raise ValueError("Query step must be finite")
    return step_seconds

  @model_validator(mode="after")
  def validate_time_range(self) -> Self:
    if self.end < self.start:
      raise ValueError("Query end must not be before start")
    return self


class PrometheusQueryResult(BaseModel):
  status: Literal["success", "empty", "partial"]
  query_type: Literal["instant", "range"]
  expression: str
  evaluation_time: datetime | None = None
  start: datetime | None = None
  end: datetime | None = None
  step_seconds: float | None = None
  timeout_seconds: int
  series_limit: int
  result_type: Literal["matrix", "vector", "scalar", "string"]
  results: Any
  result_count: int
  sample_count: int
  warnings: list[str] = Field(default_factory=list)
  infos: list[str] = Field(default_factory=list)
  partial: bool = False
  truncated: bool = False
