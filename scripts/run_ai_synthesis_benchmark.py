from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

from app.services.gemini_synthesis_service import (  # noqa: E402
  GeminiSynthesisError,
  GEMINI_MODEL,
  synthesize_evidence,
  build_synthesis_input,
)
from scripts.incident_benchmark_data import SCENARIOS  # noqa: E402
from scripts.run_incident_benchmark import _load_labels  # noqa: E402


def _citation_ids(result: Any) -> list[str]:
  return [
    evidence_id
    for finding in result.report.findings
    for evidence_id in finding.evidence_ids
  ]


async def _synthesize_scenarios(
  scenarios: list[dict[str, Any]],
  api_key: str,
  client: httpx.AsyncClient,
) -> list[tuple[dict[str, Any], Any]]:
  results = []
  for scenario in scenarios:
    context, evidence_ids = build_synthesis_input(scenario)
    result = await synthesize_evidence(
      context,
      evidence_ids,
      api_key,
      client,
    )
    results.append((scenario, result))
  return results


async def evaluate_synthetic_scenarios(
  api_key: str,
  scenario_ids: set[str] | None = None,
  client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
  scenarios = [
    scenario
    for scenario in SCENARIOS
    if scenario_ids is None or scenario["id"] in scenario_ids
  ]
  if not scenarios:
    raise ValueError("No matching synthetic benchmark scenarios were selected.")
  if scenario_ids is not None:
    unknown_ids = scenario_ids - {scenario["id"] for scenario in SCENARIOS}
    if unknown_ids:
      raise ValueError(
        "Unknown synthetic benchmark scenario IDs: "
        + ", ".join(sorted(unknown_ids)),
      )

  if client is None:
    async with httpx.AsyncClient(follow_redirects=False) as request_client:
      model_results = await _synthesize_scenarios(
        scenarios,
        api_key,
        request_client,
      )
  else:
    model_results = await _synthesize_scenarios(scenarios, api_key, client)

  labels_by_id = {
    item["scenario_id"]: item
    for item in _load_labels()["scenarios"]
  }
  evaluated_scenarios = []
  total_citations = 0
  relevant_citations = 0
  correct_abstentions = 0
  expected_abstentions = 0
  correct_abstention_classifications = 0

  for scenario, result in model_results:
    label = labels_by_id[scenario["id"]]
    citations = _citation_ids(result)
    relevant_ids = set(label["relevant_evidence_ids"])
    relevant_count = sum(
      evidence_id in relevant_ids
      for evidence_id in citations
    )
    expected_abstention = label["expected_abstention"]
    predicted_abstention = result.report.status == "inconclusive"
    total_citations += len(citations)
    relevant_citations += relevant_count
    expected_abstentions += expected_abstention
    correct_abstentions += expected_abstention and predicted_abstention
    correct_abstention_classifications += (
      expected_abstention == predicted_abstention
    )
    evaluated_scenarios.append({
      "scenario_id": scenario["id"],
      "expected_cause": label["expected_cause"],
      "expected_abstention": expected_abstention,
      "predicted_status": result.report.status,
      "abstention_correct": expected_abstention == predicted_abstention,
      "relevant_evidence_ids": label["relevant_evidence_ids"],
      "distractor_evidence_ids": label["distractor_evidence_ids"],
      "cited_evidence_ids": citations,
      "citation_precision": (
        relevant_count / len(citations)
        if citations
        else None
      ),
      "input_tokens": result.input_tokens,
      "output_tokens": result.output_tokens,
      "provider_attempts": result.provider_attempts,
      "report": result.report.model_dump(mode="json"),
    })

  return {
    "benchmark_version": "1.0",
    "model": GEMINI_MODEL,
    "mode": "synthetic_only_model_evaluation",
    "model_calls": len(model_results),
    "live_provider_calls": sum(
      result.provider_attempts
      for _, result in model_results
    ),
    "real_incident_data_sent": False,
    "citation_validity": "all citations resolved to supplied fixture evidence",
    "citation_precision": (
      relevant_citations / total_citations
      if total_citations
      else None
    ),
    "abstention_accuracy": (
      correct_abstention_classifications / len(model_results)
      if model_results
      else None
    ),
    "abstention_recall": (
      correct_abstentions / expected_abstentions
      if expected_abstentions
      else None
    ),
    "root_cause_accuracy": None,
    "human_adjudication_required": True,
    "scenarios": evaluated_scenarios,
  }


async def _run(args: argparse.Namespace) -> int:
  if not args.confirm_no_billing:
    raise ValueError(
      "Confirm that the Google Cloud project has no active billing account "
      "before using the unpaid Gemini API tier.",
    )
  api_key = os.environ.get("GEMINI_API_KEY")
  if not api_key:
    raise ValueError(
      "Set GEMINI_API_KEY in the local environment; never put the key in "
      "source control or chat.",
    )
  report = await evaluate_synthetic_scenarios(
    api_key,
    {args.scenario_id} if args.scenario_id else None,
  )
  rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
  if args.output is None:
    sys.stdout.write(rendered)
  else:
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote synthetic-only AI report to {args.output}")
  return 0


def main() -> int:
  parser = argparse.ArgumentParser(
    description=(
      "Evaluate Gemini synthesis using only the synthetic incident fixtures."
    ),
  )
  parser.add_argument(
    "--scenario-id",
    help="Run one known synthetic case instead of the full corpus.",
  )
  parser.add_argument(
    "--output",
    type=Path,
    help="Write the synthetic-only JSON report to this path.",
  )
  parser.add_argument(
    "--confirm-no-billing",
    action="store_true",
    help=(
      "Confirm that the Google Cloud project used by GEMINI_API_KEY has no "
      "active billing account. This is required to maintain the $0 cap."
    ),
  )
  args = parser.parse_args()
  try:
    return asyncio.run(_run(args))
  except (GeminiSynthesisError, ValueError) as error:
    parser.error(str(error))
  return 2


if __name__ == "__main__":
  raise SystemExit(main())
