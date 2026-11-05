import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

from app.schemas.incident_schema import IncidentResponse


class IncidentContextEvidence(BaseModel):
  id: uuid.UUID
  evidence_type: Literal[
    "manual_report",
    "webhook_payload",
    "alertmanager_notification",
    "grafana_notification",
    "loki_logs",
    "github_context",
    "trace_spans",
    "docker_investigation",
    "prometheus_metrics",
  ]
  source_id: uuid.UUID | None
  source_event_id: uuid.UUID | None
  created_at: datetime
  retrieved_at: datetime | None
  query_hash: str | None
  query_time_range: dict[str, str | int | float] | None
  status: str | None
  record_count: int | None
  sample_count: int | None
  span_count: int | None
  warnings_count: int
  unavailable_components: list[str]
  partial: bool
  truncated: bool
  content_is_untrusted: Literal[True] = True


class IncidentContextTimelineEvent(BaseModel):
  id: str
  evidence_id: uuid.UUID | None
  evidence_type: str | None
  event_type: str
  occurred_at: datetime | None
  source_timestamp: str | None
  timestamp_kind: str
  summary: str
  details: dict[str, Any] | None = None


class IncidentContextTimeRange(BaseModel):
  start: datetime | None
  end: datetime | None


class IncidentContextCorrelation(BaseModel):
  left_evidence_id: uuid.UUID
  right_evidence_id: uuid.UUID
  kind: Literal[
    "shared_trace_id",
    "shared_service",
    "shared_instance",
    "shared_commit_sha",
    "shared_workflow_run",
    "shared_container_id",
    "shared_repository",
  ]
  value: str
  explanation: str
  left_time_range: IncidentContextTimeRange | None
  right_time_range: IncidentContextTimeRange | None


class IncidentContextEvidenceTypeCount(BaseModel):
  evidence_type: str
  count: int


class IncidentContextSourceCoverage(BaseModel):
  source_type: str
  configured_count: int
  enabled_count: int
  evidence_count: int


class IncidentContextResponse(BaseModel):
  incident: IncidentResponse
  generated_at: datetime
  evidence: list[IncidentContextEvidence]
  timeline: list[IncidentContextTimelineEvent]
  correlations: list[IncidentContextCorrelation]
  evidence_type_counts: list[IncidentContextEvidenceTypeCount]
  source_coverage: list[IncidentContextSourceCoverage]
  evidence_limit: int
  timeline_limit: int
  correlation_limit: int
  total_evidence_count: int
  evidence_truncated: bool
  timeline_truncated: bool
  metric_series_truncated: bool
  metric_transitions_truncated: bool
  correlations_truncated: bool
  gaps: list[str]
  content_is_untrusted: Literal[True] = True
