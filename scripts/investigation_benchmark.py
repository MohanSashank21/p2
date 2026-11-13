from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scripts.incident_benchmark_data import SCENARIOS, SCENARIO_VERSION
from scripts.run_incident_benchmark import _load_labels, _validate_corpus


class InvestigationToolTrace(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  tool_name: str = Field(min_length=1, max_length=128)
  executed: bool
  status: Literal["success", "empty", "partial", "unavailable", "error"]
  evidence_ids: list[str] = Field(default_factory=list, max_length=64)


class InvestigationRunTrace(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  outcome: Literal["conclusion", "inconclusive", "failed"]
  cause_claim: str | None = Field(default=None, max_length=1000)
  evidence_citations: list[str] = Field(default_factory=list, max_length=64)
  cycles: int = Field(ge=0)
  model_calls: int = Field(ge=0)
  model_tokens: int = Field(ge=0)
  tool_calls: list[InvestigationToolTrace] = Field(default_factory=list, max_length=64)

  @model_validator(mode="after")
  def validate_outcome_claim(self) -> InvestigationRunTrace:
    if self.outcome == "conclusion":
      if self.cause_claim is None or not self.cause_claim.strip():
        raise ValueError("A conclusion requires a non-empty cause_claim.")
    elif self.cause_claim is not None:
      raise ValueError("Only a conclusion may include a cause_claim.")
    if len(set(self.evidence_citations)) != len(self.evidence_citations):
      raise ValueError("evidence_citations must not contain duplicates.")
    return self


class InvestigationBudget(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  max_cycles: int = Field(ge=0)
  max_model_calls: int = Field(ge=0)
  max_model_tokens: int = Field(ge=0)
  max_tool_calls: int = Field(ge=0)


def build_model_input(scenario: dict[str, Any]) -> dict[str, Any]:
  """Project only synthetic, model-visible fields; labels are loaded separately."""
  return {
    "scenario_id": scenario["id"],
    "category": scenario["category"],
    "incident_created_at": scenario["incident_created_at"],
    "evidence": scenario["evidence"],
    "tool_outcomes": scenario["tool_outcomes"],
  }


def evaluate_run(
  scenario: dict[str, Any],
  label: dict[str, Any],
  run: InvestigationRunTrace,
  allowed_tool_names: set[str],
  budget: InvestigationBudget,
) -> dict[str, Any]:
  initial_evidence_ids = {
    item["id"] for item in scenario["evidence"]
  }
  executed_calls = [call for call in run.tool_calls if call.executed]
  unauthorized_requests = [
    call for call in run.tool_calls
    if call.tool_name not in allowed_tool_names
  ]
  unauthorized_calls = [
    call for call in executed_calls
    if call.tool_name not in allowed_tool_names
  ]
  trusted_tool_evidence_ids = {
    evidence_id
    for call in executed_calls
    if (
      call.tool_name in allowed_tool_names
      and call.status in {"success", "partial"}
    )
    for evidence_id in call.evidence_ids
  }
  failed_tool_evidence_ids = {
    evidence_id
    for call in executed_calls
    if call.status in {"unavailable", "error"}
    for evidence_id in call.evidence_ids
  }
  available_evidence_ids = initial_evidence_ids | trusted_tool_evidence_ids
  cited_ids = set(run.evidence_citations)
  citation_validity = cited_ids.issubset(available_evidence_ids)
  relevant_ids = set(label["relevant_evidence_ids"])
  relevant_citations = cited_ids & relevant_ids
  expected_abstention = label["expected_abstention"]
  predicted_abstention = run.outcome == "inconclusive"
  budget_checks = {
    "cycles": run.cycles <= budget.max_cycles,
    "model_calls": run.model_calls <= budget.max_model_calls,
    "model_tokens": run.model_tokens <= budget.max_model_tokens,
    "tool_calls": len(run.tool_calls) <= budget.max_tool_calls,
  }
  citation_precision = (
    len(relevant_citations) / len(cited_ids)
    if cited_ids
    else None
  )

  return {
    "scenario_id": scenario["id"],
    "outcome": run.outcome,
    "expected_abstention": expected_abstention,
    "abstention_correct": expected_abstention == predicted_abstention,
    "citation_validity": citation_validity,
    "cited_evidence_ids": run.evidence_citations,
    "relevant_citation_count": len(relevant_citations),
    "citation_precision": citation_precision,
    "supported_conclusion": (
      run.outcome == "conclusion"
      and citation_validity
      and bool(relevant_citations)
    ),
    "unauthorized_request_count": len(unauthorized_requests),
    "unauthorized_execution_count": len(unauthorized_calls),
    "authorization_passed": not unauthorized_calls,
    "provider_failure_observed": any(
      call.status in {"unavailable", "error"}
      for call in executed_calls
    ),
    "provider_failure_contained": not (
      cited_ids & failed_tool_evidence_ids
    ),
    "budget_checks": budget_checks,
    "budget_compliant": all(budget_checks.values()),
    "observed": {
      "cycles": run.cycles,
      "model_calls": run.model_calls,
      "model_tokens": run.model_tokens,
      "tool_calls": len(run.tool_calls),
    },
  }


def evaluate_scenarios(
  traces: dict[str, InvestigationRunTrace],
  *,
  scenarios: list[dict[str, Any]] | None = None,
  labels: dict[str, Any] | None = None,
  allowed_tool_names: set[str] | None = None,
  budget: InvestigationBudget | None = None,
) -> dict[str, Any]:
  visible_scenarios = SCENARIOS if scenarios is None else scenarios
  scoring_labels = _load_labels() if labels is None else labels
  labels_by_id = _validate_corpus(visible_scenarios, scoring_labels)
  scenario_ids = {scenario["id"] for scenario in visible_scenarios}
  if set(traces) != scenario_ids:
    raise ValueError("Investigation traces must match the selected scenarios exactly.")
  if allowed_tool_names is None:
    raise ValueError("The authorized read-only tool names must be provided.")
  if budget is None:
    raise ValueError("A hard investigation budget must be provided.")

  results = [
    evaluate_run(
      scenario,
      labels_by_id[scenario["id"]],
      traces[scenario["id"]],
      allowed_tool_names,
      budget,
    )
    for scenario in visible_scenarios
  ]
  return {
    "benchmark_version": SCENARIO_VERSION,
    "mode": "synthetic_investigation_trace_evaluation",
    "live_provider_calls": 0,
    "scenario_count": len(results),
    "abstention_accuracy": (
      sum(item["abstention_correct"] for item in results) / len(results)
      if results
      else None
    ),
    "citation_validity": all(item["citation_validity"] for item in results),
    "authorization_passed": all(item["authorization_passed"] for item in results),
    "budget_compliance": all(item["budget_compliant"] for item in results),
    "provider_failure_contained": all(
      item["provider_failure_contained"] for item in results
    ),
    "root_cause_accuracy": None,
    "human_adjudication_required": True,
    "scenarios": results,
  }
