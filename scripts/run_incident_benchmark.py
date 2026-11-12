from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from app.services.incident_context_service import (  # noqa: E402
  _MetricTimelineBudget,
  _append_timeline_events,
  _correlations,
)
from scripts.incident_benchmark_data import SCENARIOS, SCENARIO_VERSION  # noqa: E402

LABELS_PATH = ROOT / "tests" / "fixtures" / "incident_benchmark" / "labels.json"
_UUID_NAMESPACE = uuid.UUID("8cf0a7f2-4ed8-4c33-80b0-962227c5a5bf")
_REQUIRED_CATEGORIES = {
  "metric_regression",
  "log_trace_correlation",
  "deployment_workflow_failure",
  "provider_outage",
  "insufficient_evidence",
  "conflicting_evidence",
}
_ALLOWED_PROVIDERS = {"docker", "github", "loki", "prometheus", "tempo"}
_ALLOWED_TOOL_STATUSES = {"success", "partial", "unavailable", "error"}


def _stable_id(scenario_id: str, evidence_id: str) -> uuid.UUID:
  return uuid.uuid5(_UUID_NAMESPACE, f"{scenario_id}:{evidence_id}")


def _expected_correlation_key(
  correlation: dict[str, Any],
) -> tuple[str, str, tuple[str, str]]:
  return (
    correlation["kind"],
    correlation["value"],
    tuple(sorted((
      correlation["left_evidence_id"],
      correlation["right_evidence_id"],
    ))),
  )


def _actual_correlation_key(
  correlation: Any,
  short_ids: dict[uuid.UUID, str],
) -> tuple[str, str, tuple[str, str]]:
  return (
    correlation.kind,
    correlation.value,
    tuple(sorted((
      short_ids[correlation.left_evidence_id],
      short_ids[correlation.right_evidence_id],
    ))),
  )


def _load_labels() -> dict[str, Any]:
  with LABELS_PATH.open(encoding="utf-8") as labels_file:
    labels = json.load(labels_file)
  if not isinstance(labels, dict) or labels.get("benchmark_version") != SCENARIO_VERSION:
    raise ValueError("Scoring labels must declare the visible corpus version.")
  if not isinstance(labels.get("scenarios"), list):
    raise ValueError("Scoring labels must contain a scenarios list.")
  return labels


def _validate_corpus(
  scenarios: list[dict[str, Any]],
  labels: dict[str, Any],
) -> dict[str, dict[str, Any]]:
  if len(scenarios) < 12:
    raise ValueError("The initial benchmark requires at least 12 scenarios.")

  scenario_ids = [scenario.get("id") for scenario in scenarios]
  if len(set(scenario_ids)) != len(scenario_ids) or any(
    not isinstance(scenario_id, str) or not scenario_id
    for scenario_id in scenario_ids
  ):
    raise ValueError("Scenario IDs must be unique non-empty strings.")

  label_rows = labels["scenarios"]
  label_ids = [row.get("scenario_id") for row in label_rows]
  if set(label_ids) != set(scenario_ids) or len(label_ids) != len(scenario_ids):
    raise ValueError("Visible scenarios and scoring labels must match one-to-one.")

  categories = {scenario.get("category") for scenario in scenarios}
  if not _REQUIRED_CATEGORIES.issubset(categories):
    missing = ", ".join(sorted(_REQUIRED_CATEGORIES - categories))
    raise ValueError(f"Benchmark is missing required categories: {missing}.")

  labels_by_id = {row["scenario_id"]: row for row in label_rows}
  for scenario in scenarios:
    scenario_id = scenario["id"]
    row = labels_by_id[scenario_id]
    evidence_ids = {
      evidence.get("id")
      for evidence in scenario.get("evidence", [])
    }
    if not evidence_ids or None in evidence_ids:
      raise ValueError(f"{scenario_id} must have identified evidence.")
    if row.get("expected_abstention") != (row.get("expected_cause") is None):
      raise ValueError(
        f"{scenario_id} must abstain exactly when it has no expected cause.",
      )
    if not isinstance(row.get("expected_abstention"), bool):
      raise ValueError(f"{scenario_id} expected_abstention must be boolean.")
    if row.get("expected_cause") is not None and not isinstance(
      row["expected_cause"],
      str,
    ):
      raise ValueError(f"{scenario_id} expected_cause must be text or null.")

    for field in ("relevant_evidence_ids", "distractor_evidence_ids"):
      values = row.get(field)
      if not isinstance(values, list) or not set(values).issubset(evidence_ids):
        raise ValueError(f"{scenario_id} has invalid {field}.")
    if (
      row["expected_cause"] is not None
      and not row["relevant_evidence_ids"]
    ):
      raise ValueError(f"{scenario_id} has a cause without relevant evidence.")
    if set(row["relevant_evidence_ids"]) & set(row["distractor_evidence_ids"]):
      raise ValueError(
        f"{scenario_id} evidence cannot be both relevant and distractor.",
      )

    queries = row.get("valid_discriminating_queries")
    if not isinstance(queries, list) or not queries:
      raise ValueError(f"{scenario_id} needs a discriminating query.")
    for query in queries:
      if (
        not isinstance(query, dict)
        or query.get("provider") not in _ALLOWED_PROVIDERS
        or not isinstance(query.get("query"), str)
        or not query["query"].strip()
        or len(query["query"]) > 1000
      ):
        raise ValueError(f"{scenario_id} has an invalid discriminating query.")

    outcomes = scenario.get("tool_outcomes")
    if not isinstance(outcomes, list) or not outcomes:
      raise ValueError(f"{scenario_id} needs at least one fixture tool outcome.")
    for outcome in outcomes:
      if (
        not isinstance(outcome, dict)
        or outcome.get("provider") not in _ALLOWED_PROVIDERS
        or outcome.get("status") not in _ALLOWED_TOOL_STATUSES
        or isinstance(outcome.get("result_count"), bool)
        or not isinstance(outcome.get("result_count"), int)
        or outcome["result_count"] < 0
        or not isinstance(outcome.get("query_id"), str)
      ):
        raise ValueError(f"{scenario_id} has an invalid tool outcome.")
  return labels_by_id


def _project_scenario(
  scenario: dict[str, Any],
  label: dict[str, Any],
) -> dict[str, Any]:
  evidence_rows = []
  source_keys = {}
  short_ids = {}
  for evidence_data in scenario["evidence"]:
    evidence_id = _stable_id(scenario["id"], evidence_data["id"])
    short_ids[evidence_id] = evidence_data["id"]
    evidence_rows.append(SimpleNamespace(
      id=evidence_id,
      incident_id=_stable_id(scenario["id"], "incident"),
      source_event_id=None,
      alertmanager_alert_id=None,
      incident_source_id=None,
      evidence_type=evidence_data["evidence_type"],
      original_content=evidence_data["original_content"],
      normalized_content=evidence_data["normalized_content"],
      created_at=datetime.fromisoformat(evidence_data["created_at"]),
    ))
    source_keys[evidence_id] = evidence_data["source_key"]

  incident = SimpleNamespace(
    id=_stable_id(scenario["id"], "incident"),
    source_event_id=None,
    created_at=datetime.fromisoformat(scenario["incident_created_at"]),
  )
  timeline = _append_timeline_events(
    incident,
    evidence_rows,
    {},
    {},
    _MetricTimelineBudget(),
  )
  correlations, correlations_truncated = _correlations(
    evidence_rows,
    source_keys=source_keys,
  )

  expected = {
    _expected_correlation_key(item)
    for item in label["expected_correlations"]
  }
  actual = {
    _actual_correlation_key(item, short_ids)
    for item in correlations
  }
  if actual != expected:
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    raise ValueError(
      f"{scenario['id']} correlation mismatch; "
      f"missing={missing!r}, unexpected={unexpected!r}.",
    )
  if correlations_truncated:
    raise ValueError(f"{scenario['id']} unexpectedly truncated correlations.")

  timeline_types = sorted({event.event_type for event in timeline})
  if not timeline_types:
    raise ValueError(f"{scenario['id']} produced no context timeline events.")

  return {
    "scenario_id": scenario["id"],
    "category": scenario["category"],
    "evidence_count": len(evidence_rows),
    "timeline_event_count": len(timeline),
    "timeline_event_types": timeline_types,
    "correlations": [
      {
        "kind": item.kind,
        "value": item.value,
        "evidence_ids": sorted((
          short_ids[item.left_evidence_id],
          short_ids[item.right_evidence_id],
        )),
      }
      for item in correlations
    ],
    "expected_abstention": label["expected_abstention"],
    "fixture_tool_outcomes": scenario["tool_outcomes"],
    "projection_check": "passed",
  }


def build_report() -> dict[str, Any]:
  labels_by_id = _validate_corpus(SCENARIOS, _load_labels())
  visible_fixture = json.dumps(
    SCENARIOS,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
  ).encode()
  projected = [
    _project_scenario(scenario, labels_by_id[scenario["id"]])
    for scenario in SCENARIOS
  ]
  return {
    "benchmark_version": SCENARIO_VERSION,
    "mode": "deterministic_synthetic_fixture_replay",
    "fixture_sha256": hashlib.sha256(visible_fixture).hexdigest(),
    "scenario_count": len(projected),
    "expected_abstention_count": sum(
      item["expected_abstention"] for item in projected
    ),
    "model_calls": 0,
    "live_provider_calls": 0,
    "root_cause_accuracy": None,
    "scenarios": projected,
    "status": "passed",
  }


def main() -> int:
  parser = argparse.ArgumentParser(
    description="Replay the synthetic M4 incident-context benchmark.",
  )
  parser.add_argument(
    "--output",
    type=Path,
    help="Write the deterministic JSON report to this path instead of stdout.",
  )
  args = parser.parse_args()
  report = build_report()
  rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
  if args.output is None:
    sys.stdout.write(rendered)
  else:
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote benchmark report to {args.output}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
