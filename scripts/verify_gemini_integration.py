from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

from app.core.config import settings  # noqa: E402
from app.services.gemini_investigation_model import (  # noqa: E402
  GeminiInvestigationModel,
  create_gemini_investigation_client,
)
from app.services.investigation_graph import ModelProviderError  # noqa: E402


def _synthetic_payload() -> tuple[dict[str, Any], uuid.UUID]:
  evidence_id = uuid.uuid4()
  return ({
    "incident_id": str(uuid.uuid4()),
    "question": (
      "The fixture contains one synthetic observation: the checkout test "
      "service returned HTTP 503. State only what this observation establishes "
      "and cite its evidence ID, or abstain if it does not support a conclusion."
    ),
    "evidence": [{
      "id": str(evidence_id),
      "evidence_type": "synthetic_observation",
      "provenance": "fixture://gemini-integration-verification",
      "content": {
        "message": "Synthetic test observation: checkout test service returned HTTP 503.",
      },
    }],
    "initial_evidence_truncated": False,
    "read_only_tools": [],
  }, evidence_id)

async def verify_gemini_integration(
  *,
  api_key: str,
  model_name: str,
  client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
  payload, evidence_id = _synthetic_payload()
  owns_client = client is None
  request_client = client or create_gemini_investigation_client()
  try:
    model = GeminiInvestigationModel(
      api_key=api_key,
      client=request_client,
      model=model_name,
    )
    try:
      input_token_count = await model.count_input_tokens(payload)
    except ModelProviderError as error:
      raise RuntimeError(f"Gemini token-count check failed: {error}") from error
    if input_token_count < 1:
      raise RuntimeError("Gemini token-count check returned zero tokens.")

    try:
      result = await model.propose(payload, max_output_tokens=None)
    except ModelProviderError as error:
      raise RuntimeError(f"Gemini generation check failed: {error}") from error

    if result.output_tokens < 1:
      raise RuntimeError("Gemini generation returned zero output tokens.")
    if result.decision.action == "tool":
      raise RuntimeError(
        "Gemini requested a tool although the verification request offered none.",
      )
    if result.decision.action == "conclude":
      if evidence_id not in result.decision.evidence_ids:
        raise RuntimeError(
          "Gemini conclusion did not cite the supplied synthetic evidence.",
        )

    return {
      "model": model_name,
      "token_count": input_token_count,
      "action": result.decision.action,
      "claim": result.decision.claim,
      "evidence_ids": [
        str(identifier) for identifier in result.decision.evidence_ids
      ],
      "input_tokens": result.input_tokens,
      "output_tokens": result.output_tokens,
    }
  finally:
    if owns_client:
      await request_client.aclose()


async def _run() -> int:
  if settings.GEMINI_API_KEY is None:
    print(
      "FAIL: GEMINI_API_KEY is not configured in the environment or project .env.",
      file=sys.stderr,
    )
    return 1
  try:
    result = await verify_gemini_integration(
      api_key=settings.GEMINI_API_KEY.get_secret_value(),
      model_name=settings.GEMINI_MODEL,
    )
  except (RuntimeError, ValueError) as error:
    print(f"FAIL: {error}", file=sys.stderr)
    return 1

  print("PASS: Gemini token counting and structured generation succeeded.")
  print(f"Model: {result['model']}")
  print(f"Decision: {result['action']}")
  print(f"Input tokens (preflight): {result['token_count']}")
  print(f"Input tokens (generation): {result['input_tokens']}")
  print(f"Output tokens (generation): {result['output_tokens']}")
  if result["claim"]:
    print(f"Response: {result['claim']}")
  else:
    print("Response: Inconclusive (the model abstained).")
  if result["evidence_ids"]:
    print(f"Cited synthetic evidence IDs: {', '.join(result['evidence_ids'])}")
  return 0


def main() -> int:
  parser = argparse.ArgumentParser(
    description=(
      "Make live Gemini token-count and generation requests using only a "
      "built-in synthetic fixture. No OpsPilot API endpoint or Docker is used."
    ),
  )
  parser.add_argument(
    "--confirm-google-data-transfer",
    action="store_true",
    help=(
      "Confirm that the synthetic prompt will be sent to Google's Gemini API "
      "and may incur usage charges under the key's project."
    ),
  )
  args = parser.parse_args()
  if not args.confirm_google_data_transfer:
    parser.error(
      "pass --confirm-google-data-transfer to send the synthetic fixture "
      "to Google's Gemini API",
    )
  return asyncio.run(_run())


if __name__ == "__main__":
  raise SystemExit(main())
