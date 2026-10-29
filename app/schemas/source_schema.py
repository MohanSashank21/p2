import uuid
from datetime import datetime
import re
from typing import Literal, Self
from pydantic import (
  AnyHttpUrl,
  BaseModel,
  ConfigDict,
  Field,
  SecretStr,
  field_validator,
  model_validator,
)


class SourceCreateRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)
  environment_id: uuid.UUID | None = None
  source_type: Literal["generic_webhook", "alertmanager", "grafana", "loki"] = (
    "generic_webhook"
  )
  loki_url: AnyHttpUrl | None = None
  loki_tenant_id: str | None = Field(default=None, max_length=255)
  loki_auth_type: Literal["none", "bearer", "basic"] = "none"
  loki_username: str | None = Field(default=None, max_length=255)
  loki_password: SecretStr | None = None
  loki_bearer_token: SecretStr | None = None

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Source name cannot be blank")
    return name

  @model_validator(mode="after")
  def validate_loki_configuration(self) -> Self:
    if self.source_type != "loki":
      if any(
        (
          self.loki_url is not None,
          self.loki_tenant_id is not None,
          self.loki_auth_type != "none",
          self.loki_username is not None,
          self.loki_password is not None,
          self.loki_bearer_token is not None,
        ),
      ):
        raise ValueError("Loki settings are only valid for Loki sources")
      return self

    _validate_loki_auth(
      self.loki_url,
      self.loki_tenant_id,
      self.loki_auth_type,
      self.loki_username,
      self.loki_password,
      self.loki_bearer_token,
    )
    return self


def _validate_loki_auth(
  loki_url: AnyHttpUrl | None,
  tenant_id: str | None,
  auth_type: Literal["none", "bearer", "basic"],
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> None:
  if loki_url is None:
    raise ValueError("loki_url is required for Loki sources")
  if loki_url.username is not None or loki_url.password is not None:
    raise ValueError("Loki URL must not contain credentials")
  if loki_url.query is not None or loki_url.fragment is not None:
    raise ValueError("Loki URL must not contain a query or fragment")
  if tenant_id is not None and any(
    ord(character) < 32 or ord(character) == 127
    for character in tenant_id
  ):
    raise ValueError("Loki tenant ID must not contain control characters")
  if auth_type == "none" and any((username, password, bearer_token)):
    raise ValueError("Credentials are not allowed when Loki auth_type is none")
  if auth_type == "bearer" and (
    bearer_token is None
    or not bearer_token.get_secret_value().strip()
    or bearer_token.get_secret_value() != bearer_token.get_secret_value().strip()
    or "\r" in bearer_token.get_secret_value()
    or "\n" in bearer_token.get_secret_value()
    or username is not None
    or password is not None
  ):
    raise ValueError("Bearer auth requires only loki_bearer_token")
  if auth_type == "basic" and (
    username is None
    or not username.strip()
    or ":" in username
    or "\r" in username
    or "\n" in username
    or password is None
    or not password.get_secret_value()
    or bearer_token is not None
  ):
    raise ValueError("Basic auth requires loki_username and loki_password")


class LokiSourceConfigurationRequest(BaseModel):
  loki_url: AnyHttpUrl
  loki_tenant_id: str | None = Field(default=None, max_length=255)
  loki_auth_type: Literal["none", "bearer", "basic"] = "none"
  loki_username: str | None = Field(default=None, max_length=255)
  loki_password: SecretStr | None = None
  loki_bearer_token: SecretStr | None = None
  enabled: bool = True

  @model_validator(mode="after")
  def validate_loki_configuration(self) -> Self:
    _validate_loki_auth(
      self.loki_url,
      self.loki_tenant_id,
      self.loki_auth_type,
      self.loki_username,
      self.loki_password,
      self.loki_bearer_token,
    )
    return self


class SourceResponse(BaseModel):
  id: uuid.UUID
  project_id: uuid.UUID
  environment_id: uuid.UUID | None
  name: str
  source_type: str
  enabled: bool
  created_at: datetime
  loki_url: str | None = None
  loki_tenant_id: str | None = None
  loki_auth_type: str | None = None
  loki_auth_configured: bool = False

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

class AlertmanagerAlertPayload(BaseModel):
  model_config = ConfigDict(extra="allow", populate_by_name=True)
  status: Literal["firing", "resolved"]
  labels: dict[str, str] = Field(default_factory=dict)
  annotations: dict[str, str] = Field(default_factory=dict)
  starts_at: datetime = Field(alias="startsAt")
  ends_at: datetime | None = Field(default=None, alias="endsAt")
  generator_url: str | None = Field(default=None, alias="generatorURL")
  fingerprint: str = Field(min_length=1, max_length=255)

  @field_validator("fingerprint")
  @classmethod
  def validate_fingerprint(cls, fingerprint: str) -> str:
    fingerprint = fingerprint.strip()
    if not fingerprint:
      raise ValueError("Fingerprint cannot be blank")
    return fingerprint

class AlertmanagerWebhookPayload(BaseModel):
  model_config = ConfigDict(extra="allow", populate_by_name=True)
  version: str | None = None
  group_key: str | None = Field(default=None, alias="groupKey")
  receiver: str | None = None
  status: Literal["firing", "resolved"] | None = None
  external_url: str | None = Field(default=None, alias="externalURL")
  group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
  common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
  common_annotations: dict[str, str] = Field(
    default_factory=dict,
    alias="commonAnnotations",
  )
  alerts: list[AlertmanagerAlertPayload] = Field(min_length=0, max_length=500)


class LokiAutomaticRetrievalResult(BaseModel):
  source_id: uuid.UUID | None = None
  status: Literal[
    "success",
    "empty",
    "already_retrieved",
    "skipped",
    "rate_limited",
    "failed",
  ]
  entry_count: int = 0
  detail: str | None = None


class AlertmanagerAlertResult(BaseModel):
  fingerprint: str
  status: Literal["firing", "resolved"]
  outcome: Literal["created", "updated", "resolved", "ignored"]
  alert_id: uuid.UUID | None = None
  incident_id: uuid.UUID | None = None
  loki_retrieval: list[LokiAutomaticRetrievalResult] = Field(default_factory=list)

class AlertmanagerWebhookResponse(BaseModel):
  received: int
  created: int
  updated: int
  resolved: int
  ignored: int
  alerts: list[AlertmanagerAlertResult]


class LokiQueryRequest(BaseModel):
  source_id: uuid.UUID
  start: datetime
  end: datetime
  labels: dict[str, str] = Field(min_length=1, max_length=10)
  limit: int = Field(default=100, ge=1, le=200)

  @field_validator("labels")
  @classmethod
  def validate_labels(cls, labels: dict[str, str]) -> dict[str, str]:
    for key, value in labels.items():
      if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
        raise ValueError("Log label names must be valid identifiers")
      if not value.strip() or len(value) > 256:
        raise ValueError("Log label values must be nonblank and at most 256 chars")
    return labels

  @model_validator(mode="after")
  def validate_time_range(self) -> Self:
    if self.start.tzinfo is None or self.end.tzinfo is None:
      raise ValueError("Loki query times must include a timezone")
    if self.end <= self.start:
      raise ValueError("Loki query end must be after start")
    if (self.end - self.start).total_seconds() > 6 * 60 * 60:
      raise ValueError("Loki query range cannot exceed six hours")
    return self


class GrafanaAlertPayload(BaseModel):
  model_config = ConfigDict(extra="allow", populate_by_name=True)
  status: Literal["firing", "resolved"]
  labels: dict[str, str] = Field(default_factory=dict)
  annotations: dict[str, str] = Field(default_factory=dict)
  starts_at: datetime = Field(alias="startsAt")
  ends_at: datetime | None = Field(default=None, alias="endsAt")
  generator_url: str | None = Field(default=None, alias="generatorURL")
  fingerprint: str = Field(min_length=1, max_length=255)
  values: dict[str, object] | None = None
  value_string: str | None = Field(default=None, alias="valueString")
  silence_url: str | None = Field(default=None, alias="silenceURL")
  dashboard_url: str | None = Field(default=None, alias="dashboardURL")
  panel_url: str | None = Field(default=None, alias="panelURL")
  image_url: str | None = Field(default=None, alias="imageURL")

  @field_validator("fingerprint")
  @classmethod
  def validate_fingerprint(cls, fingerprint: str) -> str:
    fingerprint = fingerprint.strip()
    if not fingerprint:
      raise ValueError("Fingerprint cannot be blank")
    return fingerprint

class GrafanaWebhookPayload(BaseModel):
  model_config = ConfigDict(extra="allow", populate_by_name=True)
  receiver: str | None = None
  status: Literal["firing", "resolved"]
  org_id: int | None = Field(default=None, alias="orgId")
  alerts: list[GrafanaAlertPayload] = Field(min_length=0, max_length=500)
  group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
  common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
  common_annotations: dict[str, str] = Field(
    default_factory=dict,
    alias="commonAnnotations"
  )
  external_url: str | None = Field(default=None, alias="externalURL")
  version: str | None = None
  group_key: str | None = Field(default=None, alias="groupKey")
  truncated_alerts: int | None = Field(default=None, alias="truncatedAlerts")
  state: str | None = None
  title: str | None = None
  message: str | None = None


class GrafanaWebhookResponse(AlertmanagerWebhookResponse):
  pass
