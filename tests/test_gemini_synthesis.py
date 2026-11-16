from __future__ import annotations
import asyncio
import json
import httpx
import pytest

from app.schemas.investigation_synthesis_schema import (
  InvestigationSynthesisReport,
  UnsupportedEvidenceCitationError,
  validate_evidence_citations,
)
from app.services.gemini_synthesis_service import (
  GEMINI_GENERATE_CONTENT_URL,
  GEMINI_MODEL,
  MAX_SYNTHESIS_INPUT_BYTES,
  MAX_SYNTHESIS_RESPONSE_BYTES,
  GeminiSynthesisConfigurationError,
  GeminiSynthesisError,
  GeminiSynthesisTimeoutError,
  build_synthesis_input,
  synthesize_evidence,
)
from scripts.incident_benchmark_data import SCENARIOS
from scripts.run_ai_synthesis_benchmark import evaluate_synthetic_scenarios

def _candidate(report: dict) -> dict:
  return {
    "candidates": [
      {
        "finishReason": "STOP",
        "content": {
          "parts": [{"text": json.dumps(report)}],
        },
      },
    ],
    "usageMetadata": {
      "promptTokenCount": 100,
      "candidatesTokenCount": 20,
    },
  }


def _valid_report(evidence_id: str) -> dict:
  return {
    "status": "conclusion",
    "findings": [
      {
        "kind": "conclusion",
        "claim": "Synthetic test finding.",
        "evidence_ids": [evidence_id],
        "confidence": "moderate",
      },
    ],
    "data_gaps": [],
    "next_steps": [],
  }


@pytest.mark.asyncio
async def test_gemini_synthesis_uses_schema_and_validates_evidence_citations():
  scenario = SCENARIOS[0]
  context, evidence_ids = build_synthesis_input(scenario)
  first_evidence_id = scenario["evidence"][0]["id"]
  requests = []

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    body = json.loads(request.content)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert body["generationConfig"]["maxOutputTokens"] == 2048
    assert body["generationConfig"]["responseSchema"]["properties"]["findings"]
    assert body["generationConfig"]["thinkingConfig"] == {
      "thinkingLevel": "medium",
    }
    assert "temperature" not in body["generationConfig"]
    system_instruction = body["systemInstruction"]["parts"][0]["text"]
    assert "6. Remediation planning" in system_instruction
    assert "7. Practicality and operational safety" in system_instruction
    assert "8. Plan contents and schema mapping" in system_instruction
    assert "11. Output contract" in system_instruction
    assert "Never execute, simulate, or" in system_instruction
    user_text = body["contents"][0]["parts"][0]["text"]
    assert "expected_cause" not in user_text
    assert "relevant_evidence_ids" not in user_text
    return httpx.Response(200, json=_candidate(_valid_report(first_evidence_id)))

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    result = await synthesize_evidence(
      context,
      evidence_ids,
      "synthetic-test-key",
      client,
    )

  assert len(requests) == 1
  assert str(requests[0].url) == GEMINI_GENERATE_CONTENT_URL
  assert requests[0].headers["x-goog-api-key"] == "synthetic-test-key"
  assert result.model == GEMINI_MODEL
  assert result.report.status == "conclusion"
  assert result.input_tokens == 100
  assert result.output_tokens == 20
  assert result.provider_attempts == 1


@pytest.mark.asyncio
async def test_synthesis_retries_one_transient_503_and_counts_attempts():
  scenario = SCENARIOS[0]
  context, evidence_ids = build_synthesis_input(scenario)
  responses = [
    httpx.Response(
      503,
      json={"error": {"status": "UNAVAILABLE"}},
    ),
    httpx.Response(200, json=_candidate(_valid_report(scenario["evidence"][0]["id"]))),
  ]
  requests = []

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    return responses.pop(0)

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    result = await synthesize_evidence(
      context,
      evidence_ids,
      "synthetic-test-key",
      client,
    )

  assert len(requests) == 2
  assert result.provider_attempts == 2


@pytest.mark.asyncio
async def test_synthetic_evaluator_runs_without_exposing_scoring_labels():
  scenario = SCENARIOS[0]

  async def handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    prompt = body["contents"][0]["parts"][0]["text"]
    assert scenario["evidence"][0]["id"] in prompt
    assert "expected_cause" not in prompt
    return httpx.Response(
      200,
      json=_candidate(_valid_report(scenario["evidence"][0]["id"])),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    report = await evaluate_synthetic_scenarios(
      "synthetic-test-key",
      {"metric-regression"},
      client,
    )

  assert report["mode"] == "synthetic_only_model_evaluation"
  assert report["model_calls"] == report["live_provider_calls"] == 1
  assert report["real_incident_data_sent"] is False
  assert report["root_cause_accuracy"] is None
  assert report["human_adjudication_required"] is True
  assert report["scenarios"][0]["scenario_id"] == "metric-regression"
  assert report["scenarios"][0]["provider_attempts"] == 1


@pytest.mark.asyncio
async def test_synthesis_rejects_missing_api_key_without_network_request():
  async def handler(_request: httpx.Request) -> httpx.Response:
    pytest.fail("A request must not be sent without an API key.")

  scenario = SCENARIOS[0]
  context, evidence_ids = build_synthesis_input(scenario)
  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    with pytest.raises(
      GeminiSynthesisConfigurationError,
      match="GEMINI_API_KEY is required",
    ):
      await synthesize_evidence(context, evidence_ids, "", client)


@pytest.mark.asyncio
async def test_synthesis_rejects_oversized_input_before_network_request():
  async def handler(_request: httpx.Request) -> httpx.Response:
    pytest.fail("Oversized input must not be sent.")

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="input limit"):
      await synthesize_evidence(
        "x" * (MAX_SYNTHESIS_INPUT_BYTES + 1),
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )


@pytest.mark.asyncio
async def test_synthesis_rejects_provider_errors_and_malformed_output():
  async def provider_error(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(429, json={"error": {"message": "sensitive details"}})

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(provider_error),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="HTTP 429") as error:
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )
  assert "sensitive details" not in str(error.value)

  attempts = 0

  async def unavailable(_request: httpx.Request) -> httpx.Response:
    nonlocal attempts
    attempts += 1
    return httpx.Response(
      503,
      json={"error": {"status": "UNAVAILABLE", "message": "internal details"}},
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(unavailable),
  ) as client:
    with pytest.raises(
      GeminiSynthesisError,
      match=r"temporarily unavailable \(HTTP 503 \(UNAVAILABLE\)\) after 2 attempt\(s\)",
    ) as unavailable_error:
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )
  assert attempts == 2
  assert "internal details" not in str(unavailable_error.value)

  async def oversized_output(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      content=b" " * (MAX_SYNTHESIS_RESPONSE_BYTES + 1),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(oversized_output),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="size limit"):
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )

  async def malformed_output(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json=_candidate({"not": "the schema"}),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(malformed_output),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="required report schema"):
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )


@pytest.mark.asyncio
async def test_synthesis_rejects_provider_timeout():
  async def timeout(_request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("timeout")

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(timeout),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="timed out"):
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )


@pytest.mark.asyncio
async def test_synthesis_enforces_total_stream_timeout(monkeypatch):
  monkeypatch.setattr(
    "app.services.gemini_synthesis_service.SYNTHESIS_TIMEOUT_SECONDS",
    0.001,
  )

  class SlowStream(httpx.AsyncByteStream):
    async def __aiter__(self):
      await asyncio.sleep(0.01)
      yield b"{}"

    async def aclose(self):
      return None

  async def slow_response(request: httpx.Request) -> httpx.Response:
    assert str(request.url) == GEMINI_GENERATE_CONTENT_URL
    return httpx.Response(200, stream=SlowStream())

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(slow_response),
  ) as client:
    with pytest.raises(GeminiSynthesisTimeoutError) as error:
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )

  assert error.value.attempts == 1


@pytest.mark.asyncio
async def test_synthesis_rejects_safety_block():
  async def safety_block(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json={
        "candidates": [
          {
            "finishReason": "SAFETY",
            "content": {"parts": []},
          },
        ],
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(safety_block),
  ) as client:
    with pytest.raises(GeminiSynthesisError, match="did not finish"):
      await synthesize_evidence(
        "{}",
        {"evidence-1"},
        "synthetic-test-key",
        client,
      )


def test_synthesis_schema_requires_supported_claim_state_and_citations():
  with pytest.raises(ValueError, match="status must match"):
    InvestigationSynthesisReport.model_validate({
      "status": "conclusion",
      "findings": [
        {
          "kind": "observation",
          "claim": "Only an observation.",
          "evidence_ids": ["evidence-1"],
          "confidence": "low",
        },
      ],
      "data_gaps": [],
      "next_steps": [],
    })


def test_synthesis_rejects_citations_outside_the_supplied_context():
  report = InvestigationSynthesisReport.model_validate(
    _valid_report("evidence-not-in-context"),
  )

  with pytest.raises(UnsupportedEvidenceCitationError) as error:
    validate_evidence_citations(report, {"evidence-1"})

  assert error.value.evidence_ids == {"evidence-not-in-context"}
