from __future__ import annotations

from scripts.incident_benchmark_data import SCENARIOS
from scripts.run_incident_benchmark import build_report


def test_incident_benchmark_replays_all_scenarios_deterministically():
  first = build_report()
  second = build_report()

  assert first == second
  assert first["benchmark_version"] == "1.0"
  assert first["mode"] == "deterministic_synthetic_fixture_replay"
  assert first["scenario_count"] == len(SCENARIOS)
  assert first["scenario_count"] >= 12
  assert first["expected_abstention_count"] == 8
  assert first["model_calls"] == 0
  assert first["live_provider_calls"] == 0
  assert first["root_cause_accuracy"] is None
  assert first["status"] == "passed"
  assert all(row["projection_check"] == "passed" for row in first["scenarios"])


def test_benchmark_visible_fixtures_do_not_contain_scoring_labels():
  forbidden_fields = {
    "expected_abstention",
    "expected_cause",
    "relevant_evidence_ids",
    "valid_discriminating_queries",
  }

  for scenario in SCENARIOS:
    assert forbidden_fields.isdisjoint(scenario)
