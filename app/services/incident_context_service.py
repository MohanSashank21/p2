from __future__ import annotations

import heapq
import json
import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource, ProviderAlert, SourceEvent
from app.schemas.incident_context_schema import (
  IncidentContextCorrelation,
  IncidentContextEvidence,
  IncidentContextEvidenceTypeCount,
  IncidentContextResponse,
  IncidentContextSourceCoverage,
  IncidentContextTimelineEvent,
  IncidentContextTimeRange,
)
from app.schemas.incident_schema import IncidentResponse

MAX_CONTEXT_EVIDENCE = 100
MAX_CONTEXT_TIMELINE = 200
MAX_CONTEXT_CORRELATIONS = 200
MAX_CONTEXT_METRIC_SERIES = MAX_CONTEXT_TIMELINE
MAX_CONTEXT_METRIC_TRANSITIONS = MAX_CONTEXT_TIMELINE
_TRACE_ID = re.compile(r"^(?:[0-9a-f]{16}|[0-9a-f]{32})$", re.IGNORECASE)
_COMMIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$", re.IGNORECASE)
_SERVICE_LABELS = {"service", "service_name", "service.name", "app"}
_INSTANCE_LABELS = {"instance"}
_COMMIT_LABELS = {"commit", "commit_sha", "git_sha", "head_sha"}
_WORKFLOW_LABELS = {"workflow_run_id", "workflow_run.id"}
_CONTAINER_LABELS = {"container_id", "container.id"}
_REPOSITORY_LABELS = {"repo", "repository", "repository.full_name"}
_MAX_CORRELATION_VALUE_LENGTH = 512
_MAX_CORRELATION_LOG_LINE_LENGTH = 64 * 1024
_NON_IDENTIFYING_LABEL_VALUES = {
  "grafana",
  "n/a",
  "na",
  "none",
  "null",
  "unknown",
  "unknown-service",
  "unknown_service",
}
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class _MetricTimelineBudget:
  def __init__(self) -> None:
    self.series_summaries_added = 0
    self.series_summaries_omitted = 0
    self.transition_candidates_seen = 0
    self.transition_candidates: list[
      tuple[tuple[int, int, str, int, int, str], str, IncidentContextTimelineEvent]
    ] = []
    self.metric_transitions_truncated = False


def _event_priority(event: IncidentContextTimelineEvent) -> int:
  return {
    "incident_created": 0,
    "source_event_received": 0,
    "alert_started": 0,
    "alert_ended": 0,
    "prometheus_metric_transition": 1,
    "container_started": 1,
    "container_finished": 1,
    "workflow_run_started": 1,
    "workflow_run_created": 1,
    "trace_span_started": 2,
    "docker_event": 2,
    "prometheus_series_observation": 3,
    "log_entry": 4,
    "workflow_run_updated": 4,
    "docker_evidence_collected": 5,
    "evidence_retrieved": 6,
    "evidence_persisted": 7,
  }.get(event.event_type, 5)


def _datetime_sort_value(value: datetime | None) -> int:
  if value is None:
    return 0
  delta = _db_datetime(value) - _EPOCH
  return (
    delta.days * 86_400_000_000
    + delta.seconds * 1_000_000
    + delta.microseconds
  )


def _select_timeline_events(
  events: list[IncidentContextTimelineEvent],
) -> tuple[list[IncidentContextTimelineEvent], bool]:
  ranked = sorted(
    events,
    key=lambda item: (
      _event_priority(item),
      item.occurred_at is None,
      -_datetime_sort_value(item.occurred_at),
      str(item.evidence_id or ""),
      item.id,
    ),
  )
  truncated = len(ranked) > MAX_CONTEXT_TIMELINE
  selected = ranked[:MAX_CONTEXT_TIMELINE]
  selected.sort(
    key=lambda item: (
      item.occurred_at is None,
      item.occurred_at or _EPOCH,
      item.evidence_id is None,
      str(item.evidence_id or ""),
      item.id,
    ),
  )
  return selected, truncated


def _db_datetime(value: datetime) -> datetime:
  if value.tzinfo is None:
    return value.replace(tzinfo=UTC)
  return value.astimezone(UTC)


def _parse_iso_timestamp(value: Any) -> datetime | None:
  if isinstance(value, datetime):
    if value.tzinfo is None or value.utcoffset() is None:
      return None
    return value.astimezone(UTC)
  if not isinstance(value, str) or not value:
    return None
  try:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
  except ValueError:
    return None
  if parsed.tzinfo is None or parsed.utcoffset() is None:
    return None
  return parsed.astimezone(UTC)


def _parse_epoch_timestamp(value: Any, *, nanoseconds: bool) -> datetime | None:
  if isinstance(value, bool) or not isinstance(
    value,
    (str, int, float, Decimal),
  ):
    return None
  try:
    seconds = Decimal(str(value))
    if not seconds.is_finite():
      return None
    if nanoseconds:
      seconds /= Decimal(1_000_000_000)
    micros = int(seconds * Decimal(1_000_000))
    return _EPOCH + timedelta(microseconds=micros)
  except (InvalidOperation, OverflowError, ValueError):
    return None


def _event(
  *,
  evidence: IncidentEvidence | None,
  event_id: str,
  event_type: str,
  occurred_at: datetime | None,
  source_timestamp: Any,
  timestamp_kind: str,
  summary: str,
  details: dict[str, Any] | None = None,
) -> IncidentContextTimelineEvent:
  if isinstance(source_timestamp, (str, int, float)):
    formatted_timestamp = str(source_timestamp)
    if len(formatted_timestamp) > 256:
      formatted_timestamp = None
  else:
    formatted_timestamp = None
  return IncidentContextTimelineEvent(
    id=event_id,
    evidence_id=evidence.id if evidence is not None else None,
    evidence_type=evidence.evidence_type if evidence is not None else None,
    event_type=event_type,
    occurred_at=occurred_at,
    source_timestamp=formatted_timestamp,
    timestamp_kind=timestamp_kind,
    summary=summary,
    details=details,
  )


def _dict(value: Any) -> dict[str, Any]:
  return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
  return value if isinstance(value, list) else []


def _add_iso_event(
  events: list[IncidentContextTimelineEvent],
  evidence: IncidentEvidence,
  suffix: str,
  event_type: str,
  timestamp: Any,
  timestamp_kind: str,
  summary: str,
) -> None:
  parsed = _parse_iso_timestamp(timestamp)
  events.append(
    _event(
      evidence=evidence,
      event_id=f"{evidence.id}:{suffix}",
      event_type=event_type,
      occurred_at=parsed,
      source_timestamp=timestamp,
      timestamp_kind=timestamp_kind,
      summary=summary,
    ),
  )


def _add_db_event(
  events: list[IncidentContextTimelineEvent],
  evidence: IncidentEvidence,
  suffix: str,
  event_type: str,
  timestamp: datetime,
  timestamp_kind: str,
  summary: str,
) -> None:
  occurred_at = _db_datetime(timestamp)
  events.append(
    _event(
      evidence=evidence,
      event_id=f"{evidence.id}:{suffix}",
      event_type=event_type,
      occurred_at=occurred_at,
      source_timestamp=timestamp.isoformat(),
      timestamp_kind=timestamp_kind,
      summary=summary,
    ),
  )


def _add_epoch_event(
  events: list[IncidentContextTimelineEvent],
  evidence: IncidentEvidence,
  suffix: str,
  event_type: str,
  timestamp: Any,
  *,
  nanoseconds: bool,
  timestamp_kind: str,
  summary: str,
) -> None:
  parsed = _parse_epoch_timestamp(timestamp, nanoseconds=nanoseconds)
  events.append(
    _event(
      evidence=evidence,
      event_id=f"{evidence.id}:{suffix}",
      event_type=event_type,
      occurred_at=parsed,
      source_timestamp=timestamp,
      timestamp_kind=timestamp_kind,
      summary=summary,
    ),
  )


def _append_prometheus_events(
  events: list[IncidentContextTimelineEvent],
  evidence: IncidentEvidence,
  budget: _MetricTimelineBudget,
) -> None:
  original = evidence.original_content
  normalized = _dict(evidence.normalized_content)
  results = _list(original.get("results"))
  result_type = str(normalized.get("result_type", ""))
  if result_type in {"scalar", "string"}:
    series_data = [
      (
        0,
        {},
        [("value", 0, results)] if len(results) == 2 else [],
      ),
    ]
  else:
    series_data = []
    for series_index, series_value in enumerate(results):
      series = _dict(series_value)
      samples: list[tuple[str, int, Any]] = []
      for field in ("value", "values", "histogram", "histograms"):
        field_value = series.get(field)
        if not isinstance(field_value, list):
          continue
        pairs = (
          [field_value]
          if field in {"value", "histogram"} and len(field_value) == 2
          else _list(field_value)
        )
        samples.extend(
          (field, sample_index, sample)
          for sample_index, sample in enumerate(pairs)
          if isinstance(sample, list) and len(sample) == 2
        )
      series_data.append(
        (series_index, _dict(series.get("metric")), samples),
      )

  for series_index, metric, samples in series_data:
    if not samples:
      continue
    if budget.series_summaries_added >= MAX_CONTEXT_METRIC_SERIES:
      budget.series_summaries_omitted += 1
      continue

    samples.sort(
      key=lambda item: (
        _parse_epoch_timestamp(item[2][0], nanoseconds=False) is None,
        _parse_epoch_timestamp(item[2][0], nanoseconds=False) or _EPOCH,
        item[0],
        item[1],
      ),
    )
    sample_count = len(samples)
    first_field, first_index, first_sample = samples[0]
    last_field, last_index, last_sample = samples[-1]
    changes: list[
      tuple[
        int,
        str,
        int,
        Any,
        Any,
        datetime | None,
        bool,
        str,
        int,
      ]
    ] = []
    for index in range(1, sample_count):
      previous_field, previous_index, previous_sample = samples[index - 1]
      current_field, current_index, current_sample = samples[index]
      if (
        previous_field != current_field
        or previous_sample[1] == current_sample[1]
      ):
        continue
      occurred_at = _parse_epoch_timestamp(
        current_sample[0],
        nanoseconds=False,
      )
      previous_number = _metric_number(previous_sample[1])
      current_number = _metric_number(current_sample[1])
      is_zero_transition = (
        previous_number is not None
        and previous_number != 0
        and current_number == 0
      )
      changes.append(
        (
          index,
          current_field,
          current_index,
          previous_sample,
          current_sample,
          occurred_at,
          is_zero_transition,
          previous_field,
          previous_index,
        ),
      )

    metric_name = metric.get("__name__")
    metric_name = (
      metric_name[:128]
      if isinstance(metric_name, str)
      else "unnamed"
    )
    display_first = _metric_value_text(first_sample[1])
    display_last = _metric_value_text(last_sample[1])
    metric_labels = {
      key[:64]: value[:128]
      for key, value in sorted(metric.items())[:20]
      if isinstance(key, str)
      and isinstance(value, str)
      and key != "__name__"
      and len(key) <= 64
      and len(value) <= 128
    }
    summary_timestamp = last_sample[0]
    summary_details = {
      "series_index": series_index,
      "metric_name": metric_name,
      "labels": metric_labels,
      "sample_count": sample_count,
      "first_sample_ref": {"field": first_field, "index": first_index},
      "first_sample_timestamp": str(first_sample[0]),
      "first_value": _timeline_metric_value(first_sample[1]),
      "first_value_is_preview": _metric_value_is_preview(first_sample[1]),
      "last_sample_ref": {"field": last_field, "index": last_index},
      "last_sample_timestamp": str(last_sample[0]),
      "last_value": _timeline_metric_value(last_sample[1]),
      "last_value_is_preview": _metric_value_is_preview(last_sample[1]),
      "value_change_count": len(changes),
    }
    events.append(
      _event(
        evidence=evidence,
        event_id=f"{evidence.id}:series:{series_index}",
        event_type="prometheus_series_observation",
        occurred_at=_parse_epoch_timestamp(
          summary_timestamp,
          nanoseconds=False,
        ),
        source_timestamp=summary_timestamp,
        timestamp_kind="series_last_sample_time",
        summary=(
          f"Prometheus series {metric_name!r}: {sample_count} sample(s), "
          f"value {display_first} -> {display_last}, "
          f"{len(changes)} value change(s)"
        ),
        details=summary_details,
      ),
    )
    budget.series_summaries_added += 1

    for (
      _sample_order,
      current_field,
      current_index,
      previous_sample,
      current_sample,
      occurred_at,
      is_zero_transition,
      previous_field,
      previous_index,
    ) in changes:
      event_id = (
        f"{evidence.id}:series:{series_index}:transition:"
        f"{current_field}:{current_index}"
      )
      event = _event(
        evidence=evidence,
        event_id=event_id,
        event_type="prometheus_metric_transition",
        occurred_at=occurred_at,
        source_timestamp=current_sample[0],
        timestamp_kind="sample_time",
        summary=(
          f"Prometheus series {metric_name!r} changed from "
          f"{_metric_value_text(previous_sample[1])} to "
          f"{_metric_value_text(current_sample[1])}"
        ),
        details={
          "series_index": series_index,
          "metric_name": metric_name,
          "labels": metric_labels,
          "previous_sample_ref": {
            "field": previous_field,
            "index": previous_index,
          },
          "sample_ref": {
            "field": current_field,
            "index": current_index,
          },
          "previous_value": _timeline_metric_value(previous_sample[1]),
          "previous_value_is_preview": _metric_value_is_preview(
            previous_sample[1],
          ),
          "value": _timeline_metric_value(current_sample[1]),
          "value_is_preview": _metric_value_is_preview(current_sample[1]),
        },
      )
      budget.transition_candidates_seen += 1
      rank = (
        1 if is_zero_transition else 0,
        _datetime_sort_value(occurred_at),
        str(evidence.id),
        series_index,
        current_index,
        event_id,
      )
      candidate = (rank, event_id, event)
      if len(budget.transition_candidates) < MAX_CONTEXT_METRIC_TRANSITIONS:
        heapq.heappush(budget.transition_candidates, candidate)
      elif rank > budget.transition_candidates[0][0]:
        heapq.heapreplace(budget.transition_candidates, candidate)
        budget.metric_transitions_truncated = True
      else:
        budget.metric_transitions_truncated = True


def _metric_number(value: Any) -> Decimal | None:
  if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
    return None
  try:
    number = Decimal(str(value))
  except InvalidOperation:
    return None
  return number if number.is_finite() else None


def _metric_value_text(value: Any) -> str:
  if isinstance(value, str):
    rendered = repr(value)
  elif isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
    rendered = str(value)
  elif isinstance(value, dict):
    rendered = "histogram"
  else:
    rendered = "value"
  return rendered[:96]


def _timeline_metric_value(value: Any) -> Any:
  if isinstance(value, dict):
    return {"type": "histogram"}
  if isinstance(value, str):
    return value[:128]
  if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
    return value
  return None


def _metric_value_is_preview(value: Any) -> bool:
  return isinstance(value, dict) or isinstance(value, str) and len(value) > 128


def _append_timeline_events(
  incident: Incident,
  evidence_rows: list[IncidentEvidence],
  source_events: dict[uuid.UUID, SourceEvent],
  alerts: dict[uuid.UUID, ProviderAlert],
  metric_budget: _MetricTimelineBudget,
) -> list[IncidentContextTimelineEvent]:
  events = [
    _event(
      evidence=None,
      event_id=f"incident:{incident.id}:created",
      event_type="incident_created",
      occurred_at=_db_datetime(incident.created_at),
      source_timestamp=incident.created_at.isoformat(),
      timestamp_kind="incident_persisted",
      summary="Incident record created",
    ),
  ]

  linked_source_event = source_events.get(incident.source_event_id)
  if linked_source_event is not None:
    events.append(
      _event(
        evidence=None,
        event_id=f"source-event:{linked_source_event.id}:received",
        event_type="source_event_received",
        occurred_at=_db_datetime(linked_source_event.received_at),
        source_timestamp=linked_source_event.received_at.isoformat(),
        timestamp_kind="source_received_at",
        summary="Incident source event received",
      ),
    )

  for evidence in evidence_rows:
    original = _dict(evidence.original_content)
    normalized = _dict(evidence.normalized_content)
    alert = alerts.get(evidence.alertmanager_alert_id)

    if evidence.evidence_type in {
      "alertmanager_notification",
      "grafana_notification",
    } and alert is not None:
      _add_db_event(
        events,
        evidence,
        "alert-start",
        "alert_started",
        alert.starts_at,
        "alert_starts_at",
        "Alert started",
      )
      if alert.ends_at is not None:
        _add_db_event(
          events,
          evidence,
          "alert-end",
          "alert_ended",
          alert.ends_at,
          "alert_ends_at",
          "Alert ended",
        )
    elif evidence.evidence_type == "loki_logs":
      for index, entry_value in enumerate(_list(original.get("entries"))):
        entry = _dict(entry_value)
        _add_epoch_event(
          events,
          evidence,
          f"log:{index}",
          "log_entry",
          entry.get("timestamp"),
          nanoseconds=True,
          timestamp_kind="log_entry_timestamp",
          summary="Loki log entry observed",
        )
        if index + 1 >= MAX_CONTEXT_TIMELINE:
          break
    elif evidence.evidence_type == "trace_spans":
      trace_span_count = 0
      for trace_index, trace_value in enumerate(_list(original.get("traces"))):
        trace = _dict(trace_value)
        for span_index, span_value in enumerate(_list(trace.get("spans"))):
          if trace_span_count >= MAX_CONTEXT_TIMELINE:
            break
          span = _dict(span_value)
          _add_epoch_event(
            events,
            evidence,
            f"span:{trace_index}:{span_index}",
            "trace_span_started",
            span.get("start_time_unix_nano"),
            nanoseconds=True,
            timestamp_kind="span_start_time",
            summary="Trace span started",
          )
          trace_span_count += 1
          if trace_span_count >= MAX_CONTEXT_TIMELINE:
            break
        if trace_span_count >= MAX_CONTEXT_TIMELINE:
          break
    elif evidence.evidence_type == "prometheus_metrics":
      _append_prometheus_events(events, evidence, metric_budget)
    elif evidence.evidence_type == "docker_investigation":
      container_evidence = _dict(normalized.get("evidence"))
      container = _dict(container_evidence.get("container"))
      state = _dict(container.get("state"))
      for name, key in (("started", "started_at"), ("finished", "finished_at")):
        timestamp = state.get(key)
        if (
          timestamp is not None
          and timestamp != ""
          and timestamp != "0001-01-01T00:00:00Z"
        ):
          _add_iso_event(
            events,
            evidence,
            f"container:{name}",
            f"container_{name}",
            timestamp,
            f"container_{key}",
            f"Container {name}",
          )
      if normalized.get("collected_at") is not None:
        _add_iso_event(
          events,
          evidence,
          "collected",
          "docker_evidence_collected",
          normalized.get("collected_at"),
          "collected_at",
          "Docker evidence collected",
        )
      for index, docker_event_value in enumerate(
        _list(container_evidence.get("events")),
      ):
        docker_event = _dict(docker_event_value)
        timestamp = docker_event.get("time_nano")
        nanoseconds = timestamp is not None
        if timestamp is None:
          timestamp = docker_event.get("time")
        _add_epoch_event(
          events,
          evidence,
          f"docker-event:{index}",
          "docker_event",
          timestamp,
          nanoseconds=nanoseconds,
          timestamp_kind="docker_event_time",
          summary="Docker container event observed",
        )
    elif evidence.evidence_type in {
      "github_context",
      "github_workflow_event",
    }:
      run = _dict(normalized.get("workflow_run"))
      for name, key in (
        ("started", "run_started_at"),
        ("created", "created_at"),
        ("updated", "updated_at"),
        ("completed", "completed_at"),
      ):
        timestamp = run.get(key)
        if timestamp is not None:
          _add_iso_event(
            events,
            evidence,
            f"workflow:{name}",
            f"workflow_run_{name}",
            timestamp,
            f"workflow_{key}",
            f"GitHub workflow run {name}",
          )

    if evidence.source_event_id is not None:
      source_event = source_events.get(evidence.source_event_id)
      if source_event is not None:
        events.append(
          _event(
            evidence=evidence,
            event_id=f"{evidence.id}:source-event-received",
            event_type="source_event_received",
            occurred_at=_db_datetime(source_event.received_at),
            source_timestamp=source_event.received_at.isoformat(),
            timestamp_kind="source_received_at",
            summary="Incident source event received",
          ),
        )
    elif not any(
      event.evidence_id == evidence.id and event.occurred_at is not None
      for event in events
    ):
      events.append(
        _event(
          evidence=evidence,
          event_id=f"{evidence.id}:persisted",
          event_type="evidence_persisted",
          occurred_at=_db_datetime(evidence.created_at),
          source_timestamp=evidence.created_at.isoformat(),
          timestamp_kind="evidence_persisted_at",
          summary="Evidence record persisted; source event time is unavailable",
        ),
      )

    if normalized.get("retrieved_at") is not None:
      _add_iso_event(
        events,
        evidence,
        "retrieved",
        "evidence_retrieved",
        normalized.get("retrieved_at"),
        "retrieved_at",
        "Evidence retrieved from integration",
      )

  events.extend(
    candidate[2]
    for candidate in sorted(
      metric_budget.transition_candidates,
      key=lambda item: item[0],
      reverse=True,
    )
  )
  return events


def _label_values(value: Any) -> dict[str, set[str]]:
  labels = _dict(value)
  result: dict[str, set[str]] = defaultdict(set)
  for key, label_value in labels.items():
    if not isinstance(key, str) or not isinstance(label_value, str):
      continue
    if len(label_value) > _MAX_CORRELATION_VALUE_LENGTH:
      continue
    normalized_key = key.lower()
    if normalized_key in _SERVICE_LABELS and label_value:
      if label_value.strip().casefold() not in _NON_IDENTIFYING_LABEL_VALUES:
        result["service"].add(label_value)
    if normalized_key in _INSTANCE_LABELS and label_value:
      if label_value.strip().casefold() not in _NON_IDENTIFYING_LABEL_VALUES:
        result["instance"].add(label_value)
    if normalized_key in _COMMIT_LABELS:
      result["commit"].add(label_value)
    if normalized_key in _WORKFLOW_LABELS:
      result["workflow"].add(label_value)
    if normalized_key in _CONTAINER_LABELS:
      result["container"].add(label_value)
    if normalized_key in _REPOSITORY_LABELS:
      result["repository"].add(label_value)
  return result


def _canonical_identifier(kind: str, value: Any) -> str | None:
  if (
    not isinstance(value, str)
    or not value
    or len(value) > _MAX_CORRELATION_VALUE_LENGTH
  ):
    return None
  if kind == "commit":
    return value.lower() if _COMMIT_SHA.fullmatch(value) else None
  if kind == "workflow":
    if not value.isascii() or not value.isdecimal() or len(value) > 20:
      return None
    numeric = int(value)
    return str(numeric) if numeric > 0 else None
  if kind == "container":
    return value.lower() if _CONTAINER_ID.fullmatch(value) else None
  if kind == "repository":
    return value
  if kind in {"service", "instance"}:
    return value
  return None


def _valid_trace_id(value: Any) -> bool:
  return (
    isinstance(value, str)
    and _TRACE_ID.fullmatch(value) is not None
    and any(character != "0" for character in value)
  )


def _trace_id_from_log_line(value: Any) -> str | None:
  if (
    not isinstance(value, str)
    or not value
    or len(value) > _MAX_CORRELATION_LOG_LINE_LENGTH
  ):
    return None
  try:
    record = json.loads(value)
  except (json.JSONDecodeError, RecursionError):
    return None
  if not isinstance(record, dict):
    return None
  for key, candidate in record.items():
    if (
      isinstance(key, str)
      and key.lower() in {"trace_id", "traceid", "trace.id"}
      and _valid_trace_id(candidate)
    ):
      return candidate.lower()
  return None


def _add_record_identifiers(
  matches: dict[tuple[str, str], set[uuid.UUID]],
  evidence_id: uuid.UUID,
  record: Any,
) -> None:
  record = _dict(record)
  values = _label_values(record)
  for kind, kind_values in values.items():
    for value in kind_values:
      canonical = _canonical_identifier(kind, value)
      if canonical is not None:
        matches[kind, canonical].add(evidence_id)
  for key, kind in (
    ("sha", "commit"),
    ("commit_sha", "commit"),
    ("head_sha", "commit"),
    ("workflow_id", "workflow"),
    ("workflow_run_id", "workflow"),
    ("container_id", "container"),
    ("full_name", "repository"),
    ("repository", "repository"),
    ("repo", "repository"),
  ):
    canonical = _canonical_identifier(kind, record.get(key))
    if canonical is not None:
      matches[kind, canonical].add(evidence_id)


def _identifiers_by_evidence(
  evidence_rows: list[IncidentEvidence],
) -> dict[tuple[str, str], set[uuid.UUID]]:
  matches: dict[tuple[str, str], set[uuid.UUID]] = defaultdict(set)
  for evidence in evidence_rows:
    original = _dict(evidence.original_content)
    normalized = _dict(evidence.normalized_content)
    records = [
      original,
      normalized,
      _dict(original.get("context")),
      _dict(original.get("workflow_run")),
      _dict(normalized.get("workflow_run")),
      _dict(original.get("commit")),
      _dict(normalized.get("commit")),
      _dict(original.get("repository")),
      _dict(normalized.get("repository")),
      _dict(original.get("labels")),
      _dict(normalized.get("labels")),
      _dict(_dict(original.get("alert")).get("labels")),
    ]
    for record in records:
      _add_record_identifiers(matches, evidence.id, record)
    for candidate in (
      _dict(original.get("workflow_run")).get("id"),
      _dict(normalized.get("workflow_run")).get("id"),
      _dict(_dict(original.get("context")).get("workflow_run")).get("id"),
    ):
      workflow_id = (
        str(candidate)
        if isinstance(candidate, int) and not isinstance(candidate, bool)
        else candidate
      )
      canonical = _canonical_identifier("workflow", workflow_id)
      if canonical is not None:
        matches["workflow", canonical].add(evidence.id)
    if evidence.evidence_type == "trace_spans":
      for trace_value in _list(original.get("traces")):
        trace = _dict(trace_value)
        for span_value in _list(trace.get("spans")):
          span = _dict(span_value)
          trace_id = span.get("trace_id", trace.get("trace_id"))
          if _valid_trace_id(trace_id):
            matches["trace", trace_id.lower()].add(evidence.id)
          service = span.get("service_name")
          if (
            isinstance(service, str)
            and service
            and len(service) <= _MAX_CORRELATION_VALUE_LENGTH
          ):
            matches["service", service].add(evidence.id)
          for attrs_key in ("attributes", "resource_attributes"):
            _add_record_identifiers(matches, evidence.id, span.get(attrs_key))
    elif evidence.evidence_type == "loki_logs":
      for entry_value in _list(original.get("entries")):
        entry = _dict(entry_value)
        labels = _dict(entry.get("labels"))
        _add_record_identifiers(matches, evidence.id, labels)
        for key in ("trace_id", "traceId", "traceID"):
          trace_id = labels.get(key)
          if _valid_trace_id(trace_id):
            matches["trace", trace_id.lower()].add(evidence.id)
        trace_id = _trace_id_from_log_line(entry.get("line"))
        if trace_id is not None:
          matches["trace", trace_id].add(evidence.id)
    elif evidence.evidence_type == "prometheus_metrics":
      for result_value in _list(original.get("results")):
        series = _dict(result_value)
        _add_record_identifiers(matches, evidence.id, series.get("metric"))
    elif evidence.evidence_type in {
      "alertmanager_notification",
      "grafana_notification",
      "webhook_payload",
    }:
      labels = normalized.get("labels")
      if not isinstance(labels, dict):
        labels = _dict(original.get("alert")).get("labels")
      if not isinstance(labels, dict):
        labels = original.get("labels")
      _add_record_identifiers(matches, evidence.id, labels)

  return matches


def _correlations(
  evidence_rows: list[IncidentEvidence],
  source_keys: dict[uuid.UUID, str] | None = None,
  time_ranges: dict[
    uuid.UUID,
    tuple[datetime | None, datetime | None],
  ] | None = None,
) -> tuple[list[IncidentContextCorrelation], bool]:
  relation_names = {
    "trace": (
      "shared_trace_id",
      "Both evidence records contain the same exact trace ID.",
    ),
    "service": (
      "shared_service",
      "Both evidence records contain the same exact service label.",
    ),
    "instance": (
      "shared_instance",
      "Both evidence records contain the same exact instance label.",
    ),
    "commit": (
      "shared_commit_sha",
      "Both evidence records contain the same full commit SHA.",
    ),
    "workflow": (
      "shared_workflow_run",
      "Both evidence records contain the same exact workflow run ID.",
    ),
    "container": (
      "shared_container_id",
      "Both evidence records contain the same exact container ID.",
    ),
    "repository": (
      "shared_repository",
      "Both evidence records contain the same exact repository identity.",
    ),
  }
  result: list[IncidentContextCorrelation] = []
  identifiers = _identifiers_by_evidence(evidence_rows)
  evidence_by_id = {item.id: item for item in evidence_rows}
  source_keys = source_keys or {}
  time_ranges = time_ranges or {}
  kind_priority = {
    "trace": 0,
    "commit": 1,
    "workflow": 2,
    "container": 3,
    "repository": 4,
    "service": 5,
    "instance": 6,
  }
  for (kind, value), ids in sorted(
    identifiers.items(),
    key=lambda item: (kind_priority[item[0][0]], item[0][1]),
  ):
    ordered_ids = sorted(ids, key=str)
    relation_type, explanation = relation_names[kind]
    for left_index, left_id in enumerate(ordered_ids):
      for right_id in ordered_ids[left_index + 1:]:
        left_source = source_keys.get(
          left_id,
          str(evidence_by_id[left_id].incident_source_id)
          if evidence_by_id[left_id].incident_source_id is not None
          else f"type:{evidence_by_id[left_id].evidence_type}",
        )
        right_source = source_keys.get(
          right_id,
          str(evidence_by_id[right_id].incident_source_id)
          if evidence_by_id[right_id].incident_source_id is not None
          else f"type:{evidence_by_id[right_id].evidence_type}",
        )
        if left_source == right_source:
          continue
        if len(result) >= MAX_CONTEXT_CORRELATIONS:
          return result, True
        left_start, left_end = time_ranges.get(left_id, (None, None))
        right_start, right_end = time_ranges.get(right_id, (None, None))
        result.append(
          IncidentContextCorrelation(
            left_evidence_id=left_id,
            right_evidence_id=right_id,
            kind=relation_type,
            value=value,
            explanation=explanation,
            left_time_range=IncidentContextTimeRange(
              start=left_start,
              end=left_end,
            )
            if left_start is not None or left_end is not None
            else None,
            right_time_range=IncidentContextTimeRange(
              start=right_start,
              end=right_end,
            )
            if right_start is not None or right_end is not None
            else None,
          ),
        )
  return result, False


def _evidence_time_ranges(
  timeline: list[IncidentContextTimelineEvent],
) -> dict[uuid.UUID, tuple[datetime | None, datetime | None]]:
  timestamps: dict[uuid.UUID, list[datetime]] = defaultdict(list)
  for event in timeline:
    if (
      event.evidence_id is None
      or event.occurred_at is None
      or event.timestamp_kind in {"evidence_persisted_at", "retrieved_at"}
    ):
      continue
    timestamps[event.evidence_id].append(_db_datetime(event.occurred_at))
  return {
    evidence_id: (min(values), max(values))
    for evidence_id, values in timestamps.items()
  }


def _context_evidence(evidence: IncidentEvidence) -> IncidentContextEvidence:
  normalized = _dict(evidence.normalized_content)
  raw_time_range = normalized.get("time_range")
  if not isinstance(raw_time_range, dict):
    raw_query = _dict(normalized.get("query"))
    raw_time_range = raw_query.get("time_range")
  if not isinstance(raw_time_range, dict):
    raw_time_range = normalized.get("query_time_range")
  query_time_range = None
  if isinstance(raw_time_range, dict):
    query_time_range = {
      key: value
      for key, value in raw_time_range.items()
      if key in {"start", "end", "step_seconds"}
      and isinstance(value, (str, int, float))
      and not isinstance(value, bool)
      and len(str(value)) <= 128
    }
    if not query_time_range:
      query_time_range = None
  retrieved_at_value = normalized.get("retrieved_at")
  if retrieved_at_value is None:
    retrieved_at_value = normalized.get("collected_at")
  warnings = normalized.get("warnings")
  infos = normalized.get("infos")
  unavailable = normalized.get("unavailable")
  if not isinstance(unavailable, list):
    unavailable = []
  retrieved_at = _parse_iso_timestamp(retrieved_at_value)
  record_count = next(
    (
      normalized[key]
      for key in ("entry_count", "result_count", "trace_count")
      if isinstance(normalized.get(key), int)
      and not isinstance(normalized.get(key), bool)
    ),
    None,
  )
  sample_count = normalized.get("sample_count")
  span_count = normalized.get("span_count")
  return IncidentContextEvidence(
    id=evidence.id,
    evidence_type=evidence.evidence_type,
    source_id=evidence.incident_source_id,
    source_event_id=evidence.source_event_id,
    created_at=_db_datetime(evidence.created_at),
    retrieved_at=retrieved_at,
    query_hash=evidence.query_hash,
    query_time_range=query_time_range,
    status=(
      normalized.get("status")
      if isinstance(normalized.get("status"), str)
      and len(normalized["status"]) <= 64
      else normalized.get("retrieval_status")
      if isinstance(normalized.get("retrieval_status"), str)
      and len(normalized["retrieval_status"]) <= 64
      else None
    ),
    record_count=record_count,
    sample_count=(
      sample_count
      if isinstance(sample_count, int) and not isinstance(sample_count, bool)
      else None
    ),
    span_count=(
      span_count
      if isinstance(span_count, int) and not isinstance(span_count, bool)
      else None
    ),
    warnings_count=len(warnings if isinstance(warnings, list) else [])
    + len(infos if isinstance(infos, list) else []),
    unavailable_components=[
      item[:64]
      for item in unavailable[:20]
      if isinstance(item, str)
    ],
    partial=bool(
      normalized.get("partial")
      or normalized.get("status") == "partial"
      or normalized.get("retrieval_status") == "partial"
    ),
    truncated=bool(
      normalized.get("truncated")
      or normalized.get("logs_truncated")
      or normalized.get("code_files_truncated")
    ),
  )


async def build_incident_context(
  session: AsyncSession,
  incident: Incident,
) -> IncidentContextResponse:
  evidence_counts_result = await session.execute(
    select(IncidentEvidence.evidence_type, func.count())
    .where(IncidentEvidence.incident_id == incident.id)
    .group_by(IncidentEvidence.evidence_type),
  )
  evidence_type_counts = [
    IncidentContextEvidenceTypeCount(evidence_type=kind, count=count)
    for kind, count in sorted(evidence_counts_result.all())
  ]
  total_evidence_count = sum(item.count for item in evidence_type_counts)

  evidence_result = await session.scalars(
    select(IncidentEvidence)
    .where(IncidentEvidence.incident_id == incident.id)
    .order_by(IncidentEvidence.created_at, IncidentEvidence.id)
    .limit(MAX_CONTEXT_EVIDENCE + 1),
  )
  fetched_evidence = list(evidence_result)
  evidence_truncated = len(fetched_evidence) > MAX_CONTEXT_EVIDENCE
  evidence_rows = fetched_evidence[:MAX_CONTEXT_EVIDENCE]

  source_coverage_result = await session.execute(
    select(
      IncidentSource.source_type,
      IncidentSource.enabled,
      func.count(func.distinct(IncidentSource.id)),
      func.count(
        func.distinct(
          case(
            (
              or_(
                IncidentEvidence.incident_source_id == IncidentSource.id,
                ProviderAlert.id.is_not(None),
                SourceEvent.id.is_not(None),
              ),
              IncidentEvidence.id,
            ),
          ),
        ),
      ),
    )
    .outerjoin(
      IncidentEvidence,
      IncidentEvidence.incident_id == incident.id,
    )
    .outerjoin(
      ProviderAlert,
      and_(
        ProviderAlert.id == IncidentEvidence.alertmanager_alert_id,
        ProviderAlert.project_id == IncidentSource.project_id,
        ProviderAlert.incident_id == incident.id,
        ProviderAlert.source_id == IncidentSource.id,
      ),
    )
    .outerjoin(
      SourceEvent,
      and_(
        SourceEvent.id == IncidentEvidence.source_event_id,
        SourceEvent.project_id == IncidentSource.project_id,
        SourceEvent.source_id == IncidentSource.id,
      ),
    )
    .where(IncidentSource.project_id == incident.project_id)
    .group_by(IncidentSource.source_type, IncidentSource.enabled),
  )
  coverage_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
  for source_type, enabled, configured_count, source_evidence_count in (
    source_coverage_result.all()
  ):
    coverage = coverage_counts[source_type]
    coverage[0] += configured_count
    coverage[1] += configured_count if enabled else 0
    coverage[2] += source_evidence_count
  source_coverage = [
    IncidentContextSourceCoverage(
      source_type=source_type,
      configured_count=counts[0],
      enabled_count=counts[1],
      evidence_count=counts[2],
    )
    for source_type, counts in sorted(coverage_counts.items())
  ]

  source_event_ids = {
    item.source_event_id
    for item in evidence_rows
    if item.source_event_id is not None
  }
  if incident.source_event_id is not None:
    source_event_ids.add(incident.source_event_id)
  source_events: dict[uuid.UUID, SourceEvent] = {}
  if source_event_ids:
    source_event_result = await session.scalars(
      select(SourceEvent).where(
        SourceEvent.id.in_(source_event_ids),
        SourceEvent.project_id == incident.project_id,
      ),
    )
    source_events = {item.id: item for item in source_event_result}

  alert_ids = {
    item.alertmanager_alert_id
    for item in evidence_rows
    if item.alertmanager_alert_id is not None
  }
  alerts: dict[uuid.UUID, ProviderAlert] = {}
  if alert_ids:
    alert_result = await session.scalars(
      select(ProviderAlert).where(
        ProviderAlert.id.in_(alert_ids),
        ProviderAlert.project_id == incident.project_id,
        ProviderAlert.incident_id == incident.id,
      ),
    )
    alerts = {item.id: item for item in alert_result}

  metric_budget = _MetricTimelineBudget()
  all_timeline_events = _append_timeline_events(
    incident,
    evidence_rows,
    source_events,
    alerts,
    metric_budget,
  )
  source_keys: dict[uuid.UUID, str] = {}
  for item in evidence_rows:
    if item.incident_source_id is not None:
      source_keys[item.id] = str(item.incident_source_id)
    elif item.alertmanager_alert_id in alerts:
      source_keys[item.id] = str(
        alerts[item.alertmanager_alert_id].source_id,
      )
    elif item.source_event_id in source_events:
      source_keys[item.id] = str(
        source_events[item.source_event_id].source_id,
      )
    elif item.evidence_type in {"github_context", "github_workflow_event"}:
      repository_id = _dict(item.normalized_content).get("repository_id")
      if isinstance(repository_id, int) and not isinstance(repository_id, bool):
        source_keys[item.id] = f"github:{repository_id}"
      else:
        source_keys[item.id] = f"type:{item.evidence_type}"
    else:
      source_keys[item.id] = f"type:{item.evidence_type}"

  correlations, correlations_truncated = _correlations(
    evidence_rows,
    source_keys,
    _evidence_time_ranges(all_timeline_events),
  )
  timeline, event_limit_truncated = _select_timeline_events(
    all_timeline_events,
  )
  metric_series_truncated = metric_budget.series_summaries_omitted > 0
  metric_transitions_truncated = metric_budget.metric_transitions_truncated
  timeline_truncated = (
    event_limit_truncated
    or metric_series_truncated
    or metric_transitions_truncated
  )
  context_evidence = [_context_evidence(item) for item in evidence_rows]

  gaps: list[str] = []
  if total_evidence_count == 0:
    gaps.append("No persisted evidence is attached to this incident.")
  if evidence_truncated:
    gaps.append(
      f"Evidence was limited to the first {MAX_CONTEXT_EVIDENCE} records.",
    )
  if timeline_truncated:
    gaps.append(
      f"Timeline events were limited to the first {MAX_CONTEXT_TIMELINE} events.",
    )
  if metric_series_truncated:
    gaps.append(
      f"{metric_budget.series_summaries_omitted} Prometheus series summary/ies were omitted; their samples remain in the referenced evidence.",
    )
  if metric_transitions_truncated:
    gaps.append(
      "Some Prometheus value transitions were omitted from the timeline; all samples remain in the referenced evidence.",
    )
  if correlations_truncated:
    gaps.append(
      f"Correlations were limited to the first {MAX_CONTEXT_CORRELATIONS} relationships.",
    )
  partial_count = sum(item.partial for item in context_evidence)
  if partial_count:
    gaps.append(f"{partial_count} evidence record(s) report partial results.")
  truncated_count = sum(item.truncated for item in context_evidence)
  if truncated_count:
    gaps.append(f"{truncated_count} evidence record(s) report truncated content.")
  unavailable_count = sum(
    len(item.unavailable_components) for item in context_evidence
  )
  if unavailable_count:
    gaps.append(
      f"{unavailable_count} integration component(s) were unavailable in persisted evidence.",
    )
  invalid_timestamp_count = sum(
    item.occurred_at is None for item in timeline
  )
  if invalid_timestamp_count:
    gaps.append(
      f"{invalid_timestamp_count} timeline item(s) have no valid, explicitly zoned source timestamp.",
    )
  no_evidence_sources = [
    coverage.source_type
    for coverage in source_coverage
    if coverage.enabled_count and not coverage.evidence_count
  ]
  if no_evidence_sources:
    gaps.append(
      "Enabled sources without evidence for this incident: "
      + ", ".join(no_evidence_sources)
      + ". This does not establish whether an integration was queried.",
    )
  gaps.append(
    "Integration execution history is not persisted; missing evidence does not prove a source was attempted, unavailable, or returned no data.",
  )

  return IncidentContextResponse(
    incident=IncidentResponse(
      id=incident.id,
      project_id=incident.project_id,
      environment_id=incident.environment_id,
      source_event_id=incident.source_event_id,
      reported_by_user_id=incident.reported_by_user_id,
      source_type=incident.source_type,
      incident_type=incident.incident_type,
      title=incident.title,
      description=incident.description,
      severity=incident.severity,
      status=incident.status,
      created_at=_db_datetime(incident.created_at),
      updated_at=_db_datetime(incident.updated_at),
      resolved_at=(
        _db_datetime(incident.resolved_at)
        if incident.resolved_at is not None
        else None
      ),
    ),
    generated_at=datetime.now(UTC),
    evidence=context_evidence,
    timeline=timeline,
    correlations=correlations,
    evidence_type_counts=evidence_type_counts,
    source_coverage=source_coverage,
    evidence_limit=MAX_CONTEXT_EVIDENCE,
    timeline_limit=MAX_CONTEXT_TIMELINE,
    correlation_limit=MAX_CONTEXT_CORRELATIONS,
    total_evidence_count=total_evidence_count,
    evidence_truncated=evidence_truncated,
    timeline_truncated=timeline_truncated,
    metric_series_truncated=metric_series_truncated,
    metric_transitions_truncated=metric_transitions_truncated,
    correlations_truncated=correlations_truncated,
    gaps=gaps,
  )
