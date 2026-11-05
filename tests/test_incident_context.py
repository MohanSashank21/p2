import json
import uuid
from datetime import UTC, datetime, timedelta

from app.db.incident import Incident, IncidentEvidence
from app.schemas.incident_context_schema import IncidentContextTimelineEvent
from app.services.incident_context_service import (
  MAX_CONTEXT_METRIC_SERIES,
  MAX_CONTEXT_METRIC_TRANSITIONS,
  MAX_CONTEXT_TIMELINE,
  MAX_CONTEXT_CORRELATIONS,
  _MetricTimelineBudget,
  _append_timeline_events,
  _append_prometheus_events,
  _context_evidence,
  _correlations,
  _parse_epoch_timestamp,
  _parse_iso_timestamp,
  _select_timeline_events,
)


def test_context_timestamp_parsing_preserves_source_zone_and_precision():
  assert _parse_iso_timestamp("2025-01-01T02:00:00+02:00") == datetime(
    2025,
    1,
    1,
    tzinfo=UTC,
  )
  assert _parse_iso_timestamp("2025-01-01T02:00:00") is None
  assert _parse_iso_timestamp("not-a-timestamp") is None
  assert _parse_epoch_timestamp(
    "1700000000123456789",
    nanoseconds=True,
  ) == datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=UTC)
  assert _parse_epoch_timestamp(
    1700000002.5,
    nanoseconds=False,
  ) == datetime(2023, 11, 14, 22, 13, 22, 500000, tzinfo=UTC)
  assert _parse_epoch_timestamp(True, nanoseconds=False) is None
  assert _parse_epoch_timestamp("not-a-number", nanoseconds=True) is None


def _evidence(
  evidence_type: str,
  original_content: dict,
  normalized_content: dict | None = None,
) -> IncidentEvidence:
  return IncidentEvidence(
    id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    evidence_type=evidence_type,
    original_content=original_content,
    normalized_content=normalized_content or {},
    created_at=datetime(2025, 1, 1, tzinfo=UTC),
  )


def test_context_correlations_require_exact_identifiers():
  trace_id = "0123456789abcdef0123456789abcdef"
  trace = _evidence(
    "trace_spans",
    {
      "traces": [
        {
          "trace_id": trace_id,
          "spans": [
            {"trace_id": trace_id, "service_name": "checkout"},
          ],
        },
      ],
    },
  )
  matching_logs = _evidence(
    "loki_logs",
    {
      "entries": [
        {
          "line": json.dumps({"trace_id": trace_id.upper()}),
          "labels": {"service_name": "checkout"},
        },
      ],
    },
  )
  similar_logs = _evidence(
    "loki_logs",
    {
      "entries": [
        {
          "labels": {
            "trace_id": trace_id[:-1] + "e",
            "service_name": "checkout-api",
          },
        },
      ],
    },
  )

  correlations, truncated = _correlations([trace, matching_logs, similar_logs])

  assert truncated is False
  assert {(item.kind, item.value) for item in correlations} == {
    ("shared_trace_id", trace_id),
    ("shared_service", "checkout"),
  }
  assert all(
    similar_logs.id not in {item.left_evidence_id, item.right_evidence_id}
    for item in correlations
  )
  assert _correlations(
    [_evidence("webhook_payload", {}), _evidence("manual_report", {})],
  ) == ([], False)
  nearby_alert = _evidence(
    "grafana_notification",
    {},
    {"labels": {"service_name": "payments"}},
  )
  nearby_logs = _evidence(
    "loki_logs",
    {"entries": [{"labels": {"service_name": "checkout"}}]},
  )
  nearby_time = datetime(2025, 1, 1, tzinfo=UTC)
  assert _correlations(
    [nearby_alert, nearby_logs],
    time_ranges={
      nearby_alert.id: (nearby_time, nearby_time),
      nearby_logs.id: (nearby_time, nearby_time),
    },
  ) == ([], False)
  generic_alert = _evidence(
    "grafana_notification",
    {},
    {
      "labels": {
        "instance": "Grafana",
        "service_name": "unknown_service",
      },
    },
  )
  generic_logs = _evidence(
    "loki_logs",
    {
      "entries": [
        {
          "labels": {
            "instance": "Grafana",
            "service_name": "unknown_service",
          },
        },
      ],
    },
  )
  assert _correlations([generic_alert, generic_logs]) == ([], False)
  assert _correlations(
    [trace, matching_logs],
    {trace.id: "same-source", matching_logs.id: "same-source"},
  ) == ([], False)
  structured_trace_log = _evidence(
    "loki_logs",
    {
      "entries": [
        {"line": json.dumps({"traceId": trace_id})},
        {"line": json.dumps({"trace_id": f"{trace_id}suffix"})},
        {"line": "plain log text with trace_id=" + trace_id},
        {"line": json.dumps({"trace_id": "0" * 32})},
      ],
    },
  )
  exact_correlations, _ = _correlations([trace, structured_trace_log])
  assert [
    (item.kind, item.value)
    for item in exact_correlations
  ] == [("shared_trace_id", trace_id)]


def test_context_correlates_exact_commit_workflow_repository_and_container_ids():
  commit_sha = "a" * 40
  container_id = "b" * 64
  github = _evidence(
    "github_context",
    {"context": {}},
    {
      "repository": "example/payments",
      "workflow_run": {"id": 1234, "head_sha": commit_sha},
      "commit": {"sha": commit_sha},
    },
  )
  deployment_event = _evidence(
    "webhook_payload",
    {
      "labels": {
        "commit_sha": commit_sha.upper(),
        "workflow_run_id": "1234",
        "repository": "example/payments",
        "container_id": container_id,
      },
    },
  )
  docker = _evidence(
    "docker_investigation",
    {},
    {"container_id": container_id},
  )
  different_commit = _evidence(
    "webhook_payload",
    {"labels": {"commit_sha": "c" * 40}},
  )

  correlations, truncated = _correlations(
    [github, deployment_event, docker, different_commit],
  )

  assert truncated is False
  assert {
    item.kind for item in correlations
  } == {
    "shared_commit_sha",
    "shared_workflow_run",
    "shared_repository",
    "shared_container_id",
  }
  assert all(
    different_commit.id not in {item.left_evidence_id, item.right_evidence_id}
    for item in correlations
  )


def test_metric_timeline_summarizes_series_and_preserves_real_value_transitions():
  evidence = _evidence(
    "prometheus_metrics",
    {
      "expression": "up",
      "results": [
        {
          "metric": {
            "__name__": "up",
            "job": "checkout",
            "instance": "checkout-1:8080",
          },
          "values": [
            [1700000000, "1"],
            [1700000015, "1"],
            [1700000030, "0"],
            [1700000045, "0"],
            [1700000060, "1"],
          ],
        },
      ],
    },
    {"result_type": "matrix", "sample_count": 5},
  )

  events: list = []
  budget = _MetricTimelineBudget()
  _append_prometheus_events(events, evidence, budget)

  summaries = [
    item for item in events
    if item.event_type == "prometheus_series_observation"
  ]
  transitions = [
    item[2] for item in budget.transition_candidates
  ]
  assert len(summaries) == 1
  assert summaries[0].evidence_id == evidence.id
  assert summaries[0].details["sample_count"] == 5
  assert summaries[0].details["first_sample_ref"] == {
    "field": "values",
    "index": 0,
  }
  assert summaries[0].details["last_sample_ref"] == {
    "field": "values",
    "index": 4,
  }
  assert summaries[0].details["value_change_count"] == 2
  assert len(transitions) == 2
  assert any(
    item.details["previous_value"] == "1"
    and item.details["value"] == "0"
    and item.occurred_at
    == datetime(2023, 11, 14, 22, 13, 50, tzinfo=UTC)
    for item in transitions
  )
  assert all(item.evidence_id == evidence.id for item in transitions)
  assert budget.series_summaries_omitted == 0
  assert budget.metric_transitions_truncated is False
  assert len(evidence.original_content["results"][0]["values"]) == 5


def test_metric_transition_and_series_budgets_are_explicit():
  evidence = _evidence(
    "prometheus_metrics",
    {
      "results": [
        {
          "metric": {"__name__": f"metric_{index}"},
          "values": [[1700000000, "1"]],
        }
        for index in range(MAX_CONTEXT_METRIC_SERIES + 1)
      ],
    },
    {"result_type": "matrix"},
  )
  events: list = []
  budget = _MetricTimelineBudget()

  _append_prometheus_events(events, evidence, budget)

  assert sum(
    item.event_type == "prometheus_series_observation" for item in events
  ) == MAX_CONTEXT_METRIC_SERIES
  assert budget.series_summaries_omitted == 1

  transition_evidence = _evidence(
    "prometheus_metrics",
    {
      "results": [
        {
          "metric": {"__name__": "flapping"},
          "values": [
            [1700000000 + index, str(index % 2)]
            for index in range(MAX_CONTEXT_METRIC_TRANSITIONS + 5)
          ],
        },
      ],
    },
    {"result_type": "matrix"},
  )
  transition_events: list = []
  transition_budget = _MetricTimelineBudget()
  _append_prometheus_events(
    transition_events,
    transition_evidence,
    transition_budget,
  )
  assert sum(
    item[2].event_type == "prometheus_metric_transition"
    for item in transition_budget.transition_candidates
  ) == MAX_CONTEXT_METRIC_TRANSITIONS
  assert transition_budget.metric_transitions_truncated is True


def test_timeline_limit_keeps_lifecycle_transitions_and_newest_events():
  events = [
    IncidentContextTimelineEvent(
      id=f"sample:{index}",
      evidence_id=None,
      evidence_type=None,
      event_type="log_entry",
      occurred_at=datetime(2025, 1, 1, tzinfo=UTC)
      + timedelta(seconds=index),
      source_timestamp=str(index),
      timestamp_kind="log_entry_timestamp",
      summary="log",
    )
    for index in range(MAX_CONTEXT_TIMELINE + 10)
  ]
  lifecycle = IncidentContextTimelineEvent(
    id="incident",
    evidence_id=None,
    evidence_type=None,
    event_type="incident_created",
    occurred_at=datetime(2024, 1, 1, tzinfo=UTC),
    source_timestamp="2024-01-01T00:00:00Z",
    timestamp_kind="incident_persisted",
    summary="incident created",
  )
  transition = IncidentContextTimelineEvent(
    id="metric-transition",
    evidence_id=None,
    evidence_type="prometheus_metrics",
    event_type="prometheus_metric_transition",
    occurred_at=datetime(2024, 6, 1, tzinfo=UTC),
    source_timestamp="1717200000",
    timestamp_kind="sample_time",
    summary="up changed from 1 to 0",
  )

  selected, truncated = _select_timeline_events(events + [lifecycle, transition])

  assert truncated is True
  assert len(selected) == MAX_CONTEXT_TIMELINE
  selected_ids = {item.id for item in selected}
  assert lifecycle.id in selected_ids
  assert transition.id in selected_ids
  assert f"sample:{MAX_CONTEXT_TIMELINE + 9}" in selected_ids
  assert "sample:0" not in selected_ids
  assert selected == sorted(
    selected,
    key=lambda item: (
      item.occurred_at is None,
      item.occurred_at,
      item.evidence_id is None,
      str(item.evidence_id or ""),
      item.id,
    ),
  )


def test_timeline_ties_use_stable_evidence_and_event_ids():
  same_time = datetime(2025, 1, 1, tzinfo=UTC)
  events = [
    IncidentContextTimelineEvent(
      id=event_id,
      evidence_id=uuid.UUID(evidence_id[-1] * 32),
      evidence_type="loki_logs",
      event_type="log_entry",
      occurred_at=same_time,
      source_timestamp="1700000000",
      timestamp_kind="log_entry_timestamp",
      summary="same-time observation",
    )
    for event_id, evidence_id in (
      ("event-b", "b"),
      ("event-a", "a"),
    )
  ]

  selected, truncated = _select_timeline_events(events)

  assert truncated is False
  assert [item.id for item in selected] == ["event-a", "event-b"]


def test_correlations_prioritize_reliable_ids_and_report_limit():
  trace_id = "1234567890abcdef1234567890abcdef"
  evidence = [
    _evidence(
      "loki_logs",
      {"entries": [{"labels": {"service_name": "checkout"}}]},
    )
    for _ in range(22)
  ]
  evidence.extend(
    [
      _evidence(
        "trace_spans",
        {
          "traces": [
            {
              "trace_id": trace_id,
              "spans": [{"trace_id": trace_id}],
            },
          ],
        },
      ),
      _evidence(
        "loki_logs",
        {"entries": [{"labels": {"trace_id": trace_id}}]},
      ),
    ],
  )
  source_keys = {item.id: f"source:{index}" for index, item in enumerate(evidence)}

  correlations, truncated = _correlations(evidence, source_keys)

  assert truncated is True
  assert len(correlations) == MAX_CONTEXT_CORRELATIONS
  assert correlations[0].kind == "shared_trace_id"
  assert correlations[0].value == trace_id
  assert _correlations(evidence, source_keys) == (correlations, True)


def test_malformed_timestamp_metadata_does_not_break_timeline_projection():
  incident = Incident(
    id=uuid.uuid4(),
    project_id=uuid.uuid4(),
    source_type="manual",
    incident_type="service_outage",
    title="Malformed metadata case",
    severity="high",
    status="open",
    created_at=datetime(2025, 1, 1, tzinfo=UTC),
    updated_at=datetime(2025, 1, 1, tzinfo=UTC),
  )
  evidence = _evidence(
    "loki_logs",
    {"entries": [{"timestamp": {"malformed": True}, "labels": []}]},
    {"retrieved_at": ["not", "an", "iso-timestamp"]},
  )

  timeline = _append_timeline_events(
    incident,
    [evidence],
    {},
    {},
    _MetricTimelineBudget(),
  )
  reference = _context_evidence(evidence)

  log_event = next(item for item in timeline if item.event_type == "log_entry")
  assert log_event.occurred_at is None
  assert log_event.source_timestamp is None
  assert any(item.event_type == "evidence_persisted" for item in timeline)
  assert reference.retrieved_at is None
