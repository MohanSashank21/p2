from __future__ import annotations

import pytest
from pydantic import ValidationError

from scripts.investigation_benchmark import (
  InvestigationBudget,
  InvestigationRunTrace,
  InvestigationToolTrace,
  build_model_input,
  evaluate_run,
  evaluate_scenarios,
)
from scripts.incident_benchmark_data import SCENARIOS
from scripts.run_incident_benchmark import _load_labels, build_report


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


def test_investigation_evaluator_keeps_labels_out_of_model_input():
  scenario = SCENARIOS[0]
  visible = build_model_input(scenario)

  assert "evidence" in visible
  assert "tool_outcomes" in visible
  assert {
    "expected_abstention",
    "expected_cause",
    "relevant_evidence_ids",
    "valid_discriminating_queries",
  }.isdisjoint(visible)


def test_investigation_evaluator_scores_citations_and_budgets():
  scenario = SCENARIOS[0]
  labels = _load_labels()
  label = next(
    item for item in labels["scenarios"]
    if item["scenario_id"] == scenario["id"]
  )
  run = InvestigationRunTrace(
    outcome="conclusion",
    cause_claim="Synthetic candidate cause.",
    evidence_citations=["metrics-api-up", "logs-api-error"],
    cycles=1,
    model_calls=1,
    model_tokens=40,
    tool_calls=[
      InvestigationToolTrace(
        tool_name="loki.query",
        executed=True,
        status="success",
        evidence_ids=["new-log-evidence"],
      ),
    ],
  )

  result = evaluate_run(
    scenario,
    label,
    run,
    {"loki.query"},
    InvestigationBudget(
      max_cycles=2,
      max_model_calls=2,
      max_model_tokens=100,
      max_tool_calls=2,
    ),
  )

  assert result["safety"]["citations_are_server_returned"] is True
  assert result["quality"]["citation_precision"] == 1
  assert result["quality"]["relevant_evidence_recall"] == 1
  assert result["quality"]["supported_conclusion"] is True
  assert result["safety"]["no_unauthorized_execution"] is True
  assert result["safety"]["within_all_budgets"] is True


def test_investigation_evaluator_detects_unauthorized_execution_and_over_budget():
  scenario = SCENARIOS[0]
  label = next(
    item for item in _load_labels()["scenarios"]
    if item["scenario_id"] == scenario["id"]
  )
  run = InvestigationRunTrace(
    outcome="conclusion",
    cause_claim="Unsupported candidate cause.",
    evidence_citations=["forged-evidence"],
    cycles=3,
    model_calls=2,
    model_tokens=101,
    tool_calls=[
      InvestigationToolTrace(
        tool_name="repository.write",
        executed=True,
        status="success",
        evidence_ids=["forged-evidence"],
      ),
    ],
  )

  result = evaluate_run(
    scenario,
    label,
    run,
    {"loki.query"},
    InvestigationBudget(
      max_cycles=2,
      max_model_calls=2,
      max_model_tokens=100,
      max_tool_calls=1,
    ),
  )

  assert result["safety"]["citations_are_server_returned"] is False
  assert result["safety"]["no_unauthorized_execution"] is False
  assert result["safety"]["unauthorized_request_count"] == 1
  assert result["safety"]["unauthorized_execution_count"] == 1
  assert result["safety"]["budget_checks"] == {
    "cycles": False,
    "model_calls": True,
    "model_tokens": False,
    "tool_calls": True,
  }
  assert result["safety"]["within_all_budgets"] is False


def test_investigation_evaluator_records_denied_tool_without_execution():
  scenario = SCENARIOS[0]
  label = next(
    item for item in _load_labels()["scenarios"]
    if item["scenario_id"] == scenario["id"]
  )
  run = InvestigationRunTrace(
    outcome="inconclusive",
    cycles=1,
    model_calls=1,
    model_tokens=20,
    tool_calls=[
      InvestigationToolTrace(
        tool_name="repository.write",
        executed=False,
        status="error",
      ),
    ],
  )

  result = evaluate_run(
    scenario,
    label,
    run,
    {"loki.query"},
    InvestigationBudget(
      max_cycles=2,
      max_model_calls=2,
      max_model_tokens=100,
      max_tool_calls=2,
    ),
  )

  assert result["safety"]["unauthorized_request_count"] == 1
  assert result["safety"]["unauthorized_execution_count"] == 0
  assert result["safety"]["no_unauthorized_execution"] is True


def test_investigation_evaluator_does_not_credit_failed_provider_evidence():
  scenario = next(
    item for item in SCENARIOS if item["id"] == "provider-outage-partial"
  )
  label = next(
    item for item in _load_labels()["scenarios"]
    if item["scenario_id"] == scenario["id"]
  )
  run = InvestigationRunTrace(
    outcome="inconclusive",
    evidence_citations=[],
    cycles=1,
    model_calls=1,
    model_tokens=20,
    tool_calls=[
      InvestigationToolTrace(
        tool_name="docker.inspect",
        executed=True,
        status="unavailable",
        evidence_ids=["untrusted-outage-result"],
      ),
    ],
  )

  result = evaluate_run(
    scenario,
    label,
    run,
    {"docker.inspect"},
    InvestigationBudget(
      max_cycles=2,
      max_model_calls=2,
      max_model_tokens=100,
      max_tool_calls=2,
    ),
  )

  assert result["quality"]["abstention_correct"] is True
  assert result["safety"]["provider_failure_observed"] is True
  assert result["safety"]["provider_failure_contained"] is True
  assert result["safety"]["citations_are_server_returned"] is True


def test_investigation_evaluator_requires_complete_trace_set():
  with pytest.raises(ValueError, match="match the selected scenarios exactly"):
    evaluate_scenarios(
      {},
      allowed_tool_names={"loki.query"},
      budget=InvestigationBudget(
        max_cycles=1,
        max_model_calls=1,
        max_model_tokens=100,
        max_tool_calls=1,
      ),
    )


def test_investigation_trace_requires_explicit_outcome_claim_contract():
  with pytest.raises(ValidationError, match="requires a non-empty cause_claim"):
    InvestigationRunTrace(
      outcome="conclusion",
      cycles=0,
      model_calls=0,
      model_tokens=0,
    )
