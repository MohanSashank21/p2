from typing import Any
from typing import Literal

from pydantic import BaseModel, Field

from app.db.incident import IncidentEvidence


class IncidentEvidenceCriteria(BaseModel):
  limit: int = Field(default=10, ge=1, le=25)
  offset: int = Field(default=0, ge=0, le=10_000)
  evidence_types: list[
    Literal[
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
  ] | None = Field(default=None, min_length=1, max_length=9)


def evidence_payload(evidence: IncidentEvidence) -> dict[str, Any]:
  return {
    "id": str(evidence.id),
    "incident_id": str(evidence.incident_id),
    "source_event_id": (
      str(evidence.source_event_id) if evidence.source_event_id else None
    ),
    "evidence_type": evidence.evidence_type,
    "incident_source_id": (
      str(evidence.incident_source_id)
      if evidence.incident_source_id
      else None
    ),
    "original_content": evidence.original_content,
    "normalized_content": evidence.normalized_content,
    "created_at": evidence.created_at.isoformat(),
  }
