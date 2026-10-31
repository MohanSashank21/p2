import uuid
from datetime import datetime
import math
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
  source_type: Literal[
    "generic_webhook",
    "alertmanager",
    "grafana",
    "loki",
    "prometheus",
    "traces",
    "docker",
  ] = "generic_webhook"
  loki_url: AnyHttpUrl | None = None
  loki_tenant_id: str | None = Field(default=None, max_length=255)
  loki_auth_type: Literal["none", "bearer", "basic"] = "none"
  loki_username: str | None = Field(default=None, max_length=255)
  loki_password: SecretStr | None = None
  loki_bearer_token: SecretStr | None = None
  prometheus_url: AnyHttpUrl | None = None
  prometheus_auth_type: Literal["none", "bearer", "basic"] = "none"
  prometheus_username: str | None = Field(default=None, max_length=255)
  prometheus_password: SecretStr | None = None
  prometheus_bearer_token: SecretStr | None = None
  trace_backend: Literal["tempo"] | None = None
  trace_url: AnyHttpUrl | None = None
  trace_tenant_id: str | None = Field(default=None, max_length=255)
  trace_auth_type: Literal["none", "bearer", "basic"] = "none"
  trace_username: str | None = Field(default=None, max_length=255)
  trace_password: SecretStr | None = None
  trace_bearer_token: SecretStr | None = None
  trace_service_name: str | None = Field(default=None, max_length=255)
  trace_resource_attributes: dict[str, str] = Field(default_factory=dict)

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Source name cannot be blank")
    return name

  @model_validator(mode="after")
  def validate_source_configuration(self) -> Self:
    has_prometheus_config = any(
      (
        self.prometheus_url is not None,
        self.prometheus_auth_type != "none",
        self.prometheus_username is not None,
        self.prometheus_password is not None,
        self.prometheus_bearer_token is not None,
      ),
    )
    if self.source_type != "prometheus" and has_prometheus_config:
      raise ValueError("Prometheus settings are only valid for Prometheus sources")
    if self.source_type == "prometheus":
      _validate_prometheus_url(self.prometheus_url)
      _validate_prometheus_auth(
        self.prometheus_auth_type,
        self.prometheus_username,
        self.prometheus_password,
        self.prometheus_bearer_token,
      )

    has_trace_config = any(
      (
        self.trace_backend is not None,
        self.trace_url is not None,
        self.trace_tenant_id is not None,
        self.trace_auth_type != "none",
        self.trace_username is not None,
        self.trace_password is not None,
        self.trace_bearer_token is not None,
        self.trace_service_name is not None,
        bool(self.trace_resource_attributes),
      ),
    )
    if self.source_type != "traces" and has_trace_config:
      raise ValueError("Trace settings are only valid for trace sources")
    if self.source_type == "traces":
      _validate_trace_configuration(
        self.trace_backend,
        self.trace_url,
        self.trace_tenant_id,
        self.trace_auth_type,
        self.trace_username,
        self.trace_password,
        self.trace_bearer_token,
        self.trace_service_name,
        self.trace_resource_attributes,
      )

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


def _validate_prometheus_url(endpoint: AnyHttpUrl | None) -> None:
  if endpoint is None:
    raise ValueError("prometheus_url is required for Prometheus sources")
  if (
    endpoint.username is not None
    or endpoint.password is not None
    or endpoint.query is not None
    or endpoint.fragment is not None
    or "\\" in endpoint.path
    or any(part in {".", ".."} for part in endpoint.path.split("/"))
  ):
    raise ValueError(
      "Prometheus URL must not contain credentials, query, fragment, or dot segments",
    )


def _validate_prometheus_auth(
  auth_type: Literal["none", "bearer", "basic"],
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> None:
  if auth_type == "none" and any((username, password, bearer_token)):
    raise ValueError("Credentials are not allowed when prometheus_auth_type is none")
  if auth_type == "bearer" and (
    bearer_token is None
    or not bearer_token.get_secret_value().strip()
    or bearer_token.get_secret_value() != bearer_token.get_secret_value().strip()
    or "\r" in bearer_token.get_secret_value()
    or "\n" in bearer_token.get_secret_value()
    or username is not None
    or password is not None
  ):
    raise ValueError("Bearer auth requires only prometheus_bearer_token")
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
    raise ValueError("Basic auth requires prometheus_username and prometheus_password")


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


class PrometheusSourceConfigurationRequest(BaseModel):
  prometheus_url: AnyHttpUrl
  prometheus_auth_type: Literal["none", "bearer", "basic"] = "none"
  prometheus_username: str | None = Field(default=None, max_length=255)
  prometheus_password: SecretStr | None = None
  prometheus_bearer_token: SecretStr | None = None
  enabled: bool = True

  @model_validator(mode="after")
  def validate_prometheus_configuration(self) -> Self:
    _validate_prometheus_url(self.prometheus_url)
    _validate_prometheus_auth(
      self.prometheus_auth_type,
      self.prometheus_username,
      self.prometheus_password,
      self.prometheus_bearer_token,
    )
    return self


def _validate_trace_configuration(
  backend: Literal["tempo"] | None,
  endpoint: AnyHttpUrl | None,
  tenant_id: str | None,
  auth_type: Literal["none", "bearer", "basic"],
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
  service_name: str | None,
  resource_attributes: dict[str, str],
) -> None:
  if backend != "tempo":
    raise ValueError("trace_backend must be tempo")
  if endpoint is None:
    raise ValueError("trace_url is required for trace sources")
  if (
    endpoint.username is not None
    or endpoint.password is not None
    or endpoint.query is not None
    or endpoint.fragment is not None
  ):
    raise ValueError("Trace URL must not contain credentials, query, or fragment")
  if tenant_id is not None and any(
    ord(character) < 32 or ord(character) == 127
    for character in tenant_id
  ):
    raise ValueError("Trace tenant ID must not contain control characters")
  if auth_type == "none" and any((username, password, bearer_token)):
    raise ValueError("Credentials are not allowed when trace_auth_type is none")
  if auth_type == "bearer" and (
    bearer_token is None
    or not bearer_token.get_secret_value().strip()
    or bearer_token.get_secret_value() != bearer_token.get_secret_value().strip()
    or "\r" in bearer_token.get_secret_value()
    or "\n" in bearer_token.get_secret_value()
    or username is not None
    or password is not None
  ):
    raise ValueError("Bearer trace authentication requires only trace_bearer_token")
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
    raise ValueError("Basic trace authentication requires trace_username and trace_password")
  if service_name is not None and not service_name.strip():
    raise ValueError("trace_service_name must not be blank")
  if len(resource_attributes) > 10:
    raise ValueError("At most ten trace resource attributes may be configured")
  for key, value in resource_attributes.items():
    if (
      re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
        key,
      ) is None
      or key.startswith(".")
      or key.endswith(".")
      or not value.strip()
      or len(value) > 256
    ):
      raise ValueError("Trace resource attributes must have valid keys and values")


class TraceSourceConfigurationRequest(BaseModel):
  trace_backend: Literal["tempo"] = "tempo"
  trace_url: AnyHttpUrl
  trace_tenant_id: str | None = Field(default=None, max_length=255)
  trace_auth_type: Literal["none", "bearer", "basic"] = "none"
  trace_username: str | None = Field(default=None, max_length=255)
  trace_password: SecretStr | None = None
  trace_bearer_token: SecretStr | None = None
  trace_service_name: str | None = Field(default=None, max_length=255)
  trace_resource_attributes: dict[str, str] = Field(default_factory=dict)
  enabled: bool = True

  @model_validator(mode="after")
  def validate_trace_source(self) -> Self:
    _validate_trace_configuration(
      self.trace_backend,
      self.trace_url,
      self.trace_tenant_id,
      self.trace_auth_type,
      self.trace_username,
      self.trace_password,
      self.trace_bearer_token,
      self.trace_service_name,
      self.trace_resource_attributes,
    )
    return self


class SourcePatchRequest(BaseModel):
  model_config = ConfigDict(extra="forbid")

  name: str | None = Field(default=None, min_length=1, max_length=120)
  enabled: bool | None = None
  environment_id: uuid.UUID | None = None
  loki_url: AnyHttpUrl | None = None
  loki_tenant_id: str | None = Field(default=None, max_length=255)
  loki_auth_type: Literal["none", "bearer", "basic"] | None = None
  loki_username: str | None = Field(default=None, max_length=255)
  loki_password: SecretStr | None = None
  loki_bearer_token: SecretStr | None = None
  prometheus_url: AnyHttpUrl | None = None
  prometheus_auth_type: Literal["none", "bearer", "basic"] | None = None
  prometheus_username: str | None = Field(default=None, max_length=255)
  prometheus_password: SecretStr | None = None
  prometheus_bearer_token: SecretStr | None = None
  trace_backend: Literal["tempo"] | None = None
  trace_url: AnyHttpUrl | None = None
  trace_tenant_id: str | None = Field(default=None, max_length=255)
  trace_auth_type: Literal["none", "bearer", "basic"] | None = None
  trace_username: str | None = Field(default=None, max_length=255)
  trace_password: SecretStr | None = None
  trace_bearer_token: SecretStr | None = None
  trace_service_name: str | None = Field(default=None, max_length=255)
  trace_resource_attributes: dict[str, str] | None = None

  @field_validator("name")
  @classmethod
  def validate_patch_name(cls, name: str | None) -> str | None:
    if name is None:
      return name
    name = name.strip()
    if not name:
      raise ValueError("Source name cannot be blank")
    return name

  @model_validator(mode="after")
  def validate_patch(self) -> Self:
    fields_set = self.model_fields_set
    if not fields_set:
      raise ValueError("At least one source field must be provided")
    for field in (
      "name",
      "enabled",
      "environment_id",
      "loki_url",
      "loki_auth_type",
      "loki_username",
      "loki_password",
      "loki_bearer_token",
      "prometheus_url",
      "prometheus_auth_type",
      "prometheus_username",
      "prometheus_password",
      "prometheus_bearer_token",
      "trace_backend",
      "trace_url",
      "trace_auth_type",
      "trace_username",
      "trace_password",
      "trace_bearer_token",
      "trace_resource_attributes",
    ):
      if (
        field in fields_set
        and getattr(self, field) is None
        and field != "environment_id"
      ):
        raise ValueError(f"{field} cannot be null")
    for prefix in ("loki", "prometheus", "trace"):
      auth_type = f"{prefix}_auth_type"
      credential_fields = (
        f"{prefix}_username",
        f"{prefix}_password",
        f"{prefix}_bearer_token",
      )
      if any(field in fields_set for field in credential_fields):
        if auth_type not in fields_set or getattr(self, auth_type) is None:
          raise ValueError(
            f"{auth_type} is required when changing credentials",
          )
        _validate_prometheus_auth(
          getattr(self, auth_type),
          getattr(self, credential_fields[0]),
          getattr(self, credential_fields[1]),
          getattr(self, credential_fields[2]),
        )
    return self


class TraceQueryRequest(BaseModel):
  source_id: uuid.UUID
  trace_id: str | None = Field(default=None, min_length=16, max_length=32)
  service_name: str | None = Field(default=None, min_length=1, max_length=255)
  span_status: Literal["error", "ok", "unset"] | None = None
  resource_attributes: dict[str, str | int | float | bool] = Field(
    default_factory=dict,
    max_length=10,
  )
  span_attributes: dict[str, str | int | float | bool] = Field(
    default_factory=dict,
    max_length=10,
  )
  start: datetime
  end: datetime
  limit: int = Field(default=5, ge=1, le=10)

  @field_validator("trace_id")
  @classmethod
  def validate_trace_id(cls, trace_id: str | None) -> str | None:
    if trace_id is not None and re.fullmatch(r"(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})", trace_id) is None:
      raise ValueError("Trace ID must be 16 or 32 hexadecimal characters")
    return trace_id

  @field_validator("service_name")
  @classmethod
  def validate_trace_service_name(cls, service_name: str | None) -> str | None:
    if service_name is not None and not service_name.strip():
      raise ValueError("service_name must not be blank")
    return service_name.strip() if service_name is not None else None

  @field_validator("resource_attributes", "span_attributes")
  @classmethod
  def validate_trace_attributes(
    cls,
    attributes: dict[str, str | int | float | bool],
  ) -> dict[str, str | int | float | bool]:
    for key, value in attributes.items():
      if (
        re.fullmatch(
          r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
          key,
        ) is None
        or key.startswith(".")
        or key.endswith(".")
        or (
          isinstance(value, str)
          and (not value.strip() or len(value) > 256)
        )
        or (
          not isinstance(value, (str, int, float, bool))
          or isinstance(value, float) and not math.isfinite(value)
        )
      ):
        raise ValueError("Trace attributes must have valid keys and values")
    return attributes

  @model_validator(mode="after")
  def validate_trace_time_range(self) -> Self:
    if self.start.tzinfo is None or self.end.tzinfo is None:
      raise ValueError("Trace query times must include a timezone")
    if self.end <= self.start:
      raise ValueError("Trace query end must be after start")
    if (self.end - self.start).total_seconds() > 6 * 60 * 60:
      raise ValueError("Trace query range cannot exceed six hours")
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
  prometheus_url: str | None = None
  prometheus_auth_type: str | None = None
  prometheus_auth_configured: bool = False
  prometheus_connection_status: Literal[
    "not_checked",
    "connected",
    "unavailable",
  ] = "not_checked"
  prometheus_last_checked_at: datetime | None = None
  trace_backend: str | None = None
  trace_url: str | None = None
  trace_tenant_id: str | None = None
  trace_auth_type: str | None = None
  trace_auth_configured: bool = False
  trace_service_name: str | None = None
  trace_resource_attributes: dict[str, str] = Field(default_factory=dict)
  trace_connection_status: Literal["not_checked", "connected", "unavailable"] = (
    "not_checked"
  )
  trace_last_checked_at: datetime | None = None

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
