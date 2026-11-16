from __future__ import annotations

import json

import httpx
import pytest

from scripts.verify_gemini_integration import verify_gemini_integration
from app.services.gemini_investigation_model import (
  GeminiInvestigationModel,
  ModelProviderError,
)


def _decision_response(
  decision: dict,
  *,
  usage: dict | None = None,
) -> dict:
  payload = {
    "candidates": [{
      "finishReason": "STOP",
      "content": {"parts": [{"text": json.dumps(decision)}]},
    }],
  }
  if usage is not None:
    payload["usageMetadata"] = usage
  return payload


def _conclusion(evidence_id: str) -> dict:
  return {
    "action": "conclude",
    "tool_name": None,
    "arguments": {},
    "claim": "The cited evidence supports this conclusion.",
    "evidence_ids": [evidence_id],
  }


@pytest.mark.asyncio
async def test_live_verifier_checks_token_count_and_valid_synthetic_citation():
  requests: list[httpx.Request] = []

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    assert request.headers["x-goog-api-key"] == "synthetic-api-key"
    body = json.loads(request.content)
    if str(request.url).endswith(":countTokens"):
      assert body["generateContentRequest"]["model"] == (
        "models/gemini-test"
      )
      return httpx.Response(200, json={"totalTokens": 80})

    text = body["contents"][0]["parts"][0]["text"]
    synthetic_payload = json.loads(text.split("\n", maxsplit=1)[1])
    evidence_id = synthetic_payload["evidence"][0]["id"]
    return httpx.Response(
      200,
      json=_decision_response(
        _conclusion(evidence_id),
        usage={
          "promptTokenCount": 80,
          "candidatesTokenCount": 12,
          "totalTokenCount": 92,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    report = await verify_gemini_integration(
      api_key="synthetic-api-key",
      model_name="gemini-test",
      client=client,
    )
    assert not client.is_closed

  assert len(requests) == 2
  assert str(requests[0].url).endswith(":countTokens")
  assert str(requests[1].url).endswith(":generateContent")
  assert report["model"] == "gemini-test"
  assert report["action"] == "conclude"
  assert report["evidence_ids"]
  assert report["input_tokens"] == 80
  assert report["output_tokens"] == 12


@pytest.mark.asyncio
async def test_live_verifier_accepts_a_valid_inconclusive_generation():
  async def handler(request: httpx.Request) -> httpx.Response:
    if str(request.url).endswith(":countTokens"):
      return httpx.Response(200, json={"totalTokens": 80})
    return httpx.Response(
      200,
      json=_decision_response(
        {
          "action": "inconclusive",
          "tool_name": None,
          "arguments": {},
          "claim": None,
          "evidence_ids": [],
        },
        usage={
          "promptTokenCount": 80,
          "candidatesTokenCount": 5,
          "totalTokenCount": 85,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    report = await verify_gemini_integration(
      api_key="synthetic-api-key",
      model_name="gemini-test",
      client=client,
    )

  assert report["action"] == "inconclusive"
  assert report["claim"] is None
  assert report["evidence_ids"] == []


@pytest.mark.asyncio
async def test_live_verifier_surfaces_provider_generation_failure():
  async def handler(request: httpx.Request) -> httpx.Response:
    if str(request.url).endswith(":countTokens"):
      return httpx.Response(200, json={"totalTokens": 80})
    return httpx.Response(
      503,
      json={"error": {"status": "UNAVAILABLE"}},
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    with pytest.raises(RuntimeError, match="Gemini generation check failed"):
      await verify_gemini_integration(
        api_key="synthetic-api-key",
        model_name="gemini-test",
        client=client,
      )


@pytest.mark.asyncio
async def test_live_verifier_does_not_cap_provider_output_tokens():
  async def handler(request: httpx.Request) -> httpx.Response:
    if str(request.url).endswith(":countTokens"):
      return httpx.Response(200, json={"totalTokens": 80})
    body = json.loads(request.content)
    assert "maxOutputTokens" not in body["generationConfig"]
    return httpx.Response(
      200,
      json=_decision_response(
        {
          "action": "inconclusive",
          "tool_name": None,
          "arguments": {},
          "claim": None,
          "evidence_ids": [],
        },
        usage={
          "promptTokenCount": 80,
          "candidatesTokenCount": 5,
          "totalTokenCount": 85,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    await verify_gemini_integration(
      api_key="synthetic-api-key",
      model_name="gemini-test",
      client=client,
    )


@pytest.mark.asyncio
async def test_gemini_adapter_uses_strict_structured_output_and_reports_usage():
  requests: list[httpx.Request] = []
  evidence_id = "7c3e91a4-b620-4f20-9e45-c29db040f056"

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    assert request.headers["x-goog-api-key"] == "synthetic-api-key"
    body = json.loads(request.content)
    if str(request.url).endswith(":countTokens"):
      assert "generateContentRequest" in body
      assert body["generateContentRequest"]["model"] == (
        "models/gemini-test"
      )
      return httpx.Response(200, json={"totalTokens": 42})
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    response_schema = body["generationConfig"]["responseSchema"]
    assert len(response_schema["anyOf"]) == 3
    tool_schema = next(
      schema
      for schema in response_schema["anyOf"]
      if schema["properties"]["action"]["enum"] == ["tool"]
    )
    assert tool_schema["properties"]["tool_name"]["enum"] == [
      "github.investigate_failed_workflow",
    ]
    assert tool_schema["properties"]["arguments"]["required"] == [
      "repository_id",
      "event_id",
    ]
    assert (
      "additionalProperties"
      not in tool_schema["properties"]["arguments"]
    )
    assert body["generationConfig"]["maxOutputTokens"] == 256
    assert body["generationConfig"]["thinkingConfig"] == {
      "thinkingLevel": "medium",
    }
    assert "temperature" not in body["generationConfig"]
    assert "untrusted incident data" in body["contents"][0]["parts"][0]["text"]
    system_instruction = body["systemInstruction"]["parts"][0]["text"]
    assert "1. Identity and role" in system_instruction
    assert "6. Hypothesis formation" in system_instruction
    assert "9. Tool discovery and selection" in system_instruction
    assert "14. Evidence citation requirements" in system_instruction
    assert "19. Strict prohibitions" in system_instruction
    assert "recommendation plan" in system_instruction
    return httpx.Response(
      200,
      json=_decision_response(
        _conclusion(evidence_id),
        usage={
          "promptTokenCount": 100,
          "candidatesTokenCount": 24,
          "totalTokenCount": 124,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
      model="gemini-test",
    )
    result = await model.propose(
      {
        "question": "Investigate the test incident.",
        "evidence": [{"id": evidence_id, "content": "untrusted"}],
        "read_only_tools": [{
          "name": "github.investigate_failed_workflow",
          "read_only": True,
          "input_schema": {
            "type": "object",
            "properties": {
              "repository_id": {"type": "integer"},
              "event_id": {"type": "string", "format": "uuid"},
            },
            "required": ["repository_id", "event_id"],
          },
        }],
      },
      max_output_tokens=256,
    )
    counted_tokens = await model.count_input_tokens({"question": "test"})

  assert len(requests) == 2
  assert str(requests[0].url).endswith("/models/gemini-test:generateContent")
  assert str(requests[1].url).endswith("/models/gemini-test:countTokens")
  assert result.input_tokens == 100
  assert result.output_tokens == 24
  assert [str(identifier) for identifier in result.decision.evidence_ids] == [
    evidence_id,
  ]
  assert counted_tokens == 42


@pytest.mark.asyncio
async def test_gemini_usage_separates_prompt_tool_thought_and_candidate_tokens():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json=_decision_response(
        {
          "action": "inconclusive",
          "tool_name": None,
          "arguments": {},
          "claim": None,
          "evidence_ids": [],
        },
        usage={
          "promptTokenCount": 100,
          "toolUsePromptTokenCount": 5,
          "thoughtsTokenCount": 300,
          "candidatesTokenCount": 24,
          "totalTokenCount": 429,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
      model="gemini-test",
    )
    result = await model.propose(
      {"question": "test"},
      max_output_tokens=1024,
    )

  assert result.input_tokens == 105
  assert result.output_tokens == 324


@pytest.mark.asyncio
@pytest.mark.parametrize(
  "response",
  [
    httpx.Response(503, json={"error": {"status": "UNAVAILABLE"}}),
    httpx.Response(200, json={"totalTokens": "not-a-number"}),
    httpx.Response(200, json={"unexpected": 42}),
  ],
)
async def test_gemini_token_count_fails_closed(response: httpx.Response):
  async def handler(_request: httpx.Request) -> httpx.Response:
    return response

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError, match="token counting"):
      await model.count_input_tokens({"question": "test"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("response", "message"),
  [
    (
      httpx.Response(
        200,
        json={
          "candidates": [{
            "finishReason": "MAX_TOKENS",
            "content": {"parts": []},
          }],
        },
      ),
      "did not complete a valid investigation decision",
    ),
    (
      httpx.Response(
        503,
        json={"error": {"status": "UNAVAILABLE"}},
      ),
      "failed temporarily at the provider",
    ),
    (
      httpx.Response(
        200,
        json=_decision_response({
          "action": "execute",
          "tool_name": None,
          "arguments": {},
          "claim": None,
          "evidence_ids": [],
        }, usage={
          "promptTokenCount": 10,
          "candidatesTokenCount": 10,
          "totalTokenCount": 20,
        }),
      ),
      "decision failed validation at: action",
    ),
    (
      httpx.Response(
        200,
        json=_decision_response(
          _conclusion("7c3e91a4-b620-4f20-9e45-c29db040f056"),
        ),
      ),
      "did not report investigation token usage",
    ),
    (
      httpx.Response(
        200,
        json=_decision_response(
          {
            "action": "inconclusive",
            "tool_name": None,
            "arguments": {},
            "claim": None,
            "evidence_ids": [],
          },
          usage={
            "promptTokenCount": 10,
            "candidatesTokenCount": 10,
            "thoughtsTokenCount": 2,
            "totalTokenCount": 20,
          },
        ),
      ),
      "invalid investigation token usage",
    ),
  ],
)
async def test_gemini_adapter_fails_closed_for_provider_or_contract_errors(
  response: httpx.Response,
  message: str,
):
  async def handler(_request: httpx.Request) -> httpx.Response:
    return response

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError, match=message):
      await model.propose({"question": "test"}, max_output_tokens=100)


@pytest.mark.asyncio
async def test_gemini_provider_http_error_has_safe_failure_code():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      400,
      json={
        "error": {
          "status": "INVALID_ARGUMENT",
          "message": "Do not persist this provider detail.",
        },
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == "gemini_invalid_request"
  assert "Do not persist this provider detail" not in error.value.failure_code
  assert "Do not persist this provider detail" not in error.value.safe_detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("status_code", "provider_status", "expected_code", "retryable"),
  [
    (429, "RESOURCE_EXHAUSTED", "gemini_rate_limited", True),
    (401, "UNAUTHENTICATED", "gemini_authentication_failed", False),
    (404, "NOT_FOUND", "gemini_model_unavailable", False),
    (400, "INVALID_ARGUMENT", "gemini_invalid_request", False),
    (503, "UNAVAILABLE", "gemini_provider_unavailable", True),
  ],
)
async def test_gemini_provider_failures_are_classified_safely(
  status_code: int,
  provider_status: str,
  expected_code: str,
  retryable: bool,
):
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      status_code,
      headers={"Retry-After": "0.25"},
      json={
        "error": {
          "status": provider_status,
          "message": "Synthetic private provider detail.",
        },
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == expected_code
  assert error.value.retryable is retryable
  assert error.value.http_status == status_code
  assert error.value.provider_status == provider_status
  assert "Synthetic private provider detail" not in error.value.safe_detail
  assert error.value.retry_after_seconds == 0.25


@pytest.mark.asyncio
async def test_gemini_classifies_unsupported_generation_configuration():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      400,
      json={
        "error": {
          "status": "INVALID_ARGUMENT",
          "message": "The requested response schema is unsupported.",
        },
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == "gemini_unsupported_configuration"
  assert "unsupported generation setting" in error.value.safe_detail


@pytest.mark.asyncio
async def test_gemini_requests_have_no_http_client_timeout():
  async def handler(_request: httpx.Request) -> httpx.Response:
    timeout = _request.extensions.get("timeout")
    assert isinstance(timeout, dict)
    assert all(value is None for value in timeout.values())
    if str(_request.url).endswith(":countTokens"):
      return httpx.Response(200, json={"totalTokens": 10})
    return httpx.Response(
      200,
      json=_decision_response(
        {
          "action": "inconclusive",
          "tool_name": None,
          "arguments": {},
          "claim": None,
          "evidence_ids": [],
        },
        usage={
          "promptTokenCount": 10,
          "candidatesTokenCount": 1,
          "totalTokenCount": 11,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    await model.count_input_tokens({"question": "test"})
    await model.propose({"question": "test"}, max_output_tokens=100)


@pytest.mark.asyncio
async def test_gemini_contract_failure_preserves_confirmed_usage():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json={
        "candidates": [{
          "finishReason": "MAX_TOKENS",
          "content": {"parts": []},
        }],
        "usageMetadata": {
          "promptTokenCount": 100,
          "candidatesTokenCount": 24,
          "totalTokenCount": 124,
        },
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == "gemini_finish_max_tokens"
  assert error.value.input_tokens == 100
  assert error.value.output_tokens == 24


@pytest.mark.asyncio
async def test_invalid_decision_reports_safe_field_path_without_model_values():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json={
        "candidates": [{
          "finishReason": "STOP",
          "content": {
            "parts": [{
              "text": json.dumps({
                "action": "conclude",
                "tool_name": None,
                "arguments": {},
                "claim": "Do not leak this model-generated claim.",
                "evidence_ids": ["not-a-uuid"],
              }),
            }],
          },
        }],
        "usageMetadata": {
          "promptTokenCount": 100,
          "candidatesTokenCount": 24,
          "totalTokenCount": 124,
        },
      },
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
      model="gemini-test",
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == "invalid_investigation_decision"
  assert "evidence_ids.0" in error.value.safe_detail
  assert "Do not leak this model-generated claim" not in error.value.safe_detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("decision", "diagnostic"),
  [
    (
      {
        "tool_name": None,
        "arguments": {},
        "claim": None,
        "evidence_ids": [],
      },
      "action:missing_field",
    ),
    (
      {
        "action": "execute",
        "tool_name": None,
        "arguments": {},
        "claim": None,
        "evidence_ids": [],
      },
      "action:invalid_enum",
    ),
    (
      {
        "action": "inconclusive",
        "tool_name": None,
        "arguments": [],
        "claim": None,
        "evidence_ids": [],
      },
      "arguments:type_mismatch",
    ),
    (
      {
        "action": "tool",
        "tool_name": "logs.query",
        "claim": None,
        "evidence_ids": [],
      },
      "arguments:missing_field",
    ),
    (
      {
        "action": "inconclusive",
        "tool_name": None,
        "arguments": {},
        "claim": None,
        "evidence_ids": [],
        "model_generated_secret": "must not appear in diagnostics",
      },
      "<additional-field>:unexpected_field",
    ),
  ],
)
async def test_decision_validation_reports_safe_field_categories(
  decision: dict,
  diagnostic: str,
):
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json=_decision_response(
        decision,
        usage={
          "promptTokenCount": 10,
          "candidatesTokenCount": 5,
          "totalTokenCount": 15,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
      model="gemini-test",
    )
    with pytest.raises(ModelProviderError) as error:
      await model.propose({"question": "test"}, max_output_tokens=100)

  assert error.value.failure_code == "invalid_investigation_decision"
  assert diagnostic in error.value.safe_detail
  assert "must not appear in diagnostics" not in error.value.safe_detail


@pytest.mark.asyncio
async def test_gemini_adapter_rejects_malformed_and_markdown_wrapped_json():
  for text in (
    '{"action":',
    '```json\n{"action":"inconclusive"}\n```',
  ):
    async def handler(_request: httpx.Request) -> httpx.Response:
      return httpx.Response(
        200,
        json={
          "candidates": [{
            "finishReason": "STOP",
            "content": {"parts": [{"text": text}]},
          }],
          "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5,
            "totalTokenCount": 15,
          },
        },
      )

    async with httpx.AsyncClient(
      transport=httpx.MockTransport(handler),
    ) as client:
      model = GeminiInvestigationModel(
        api_key="synthetic-api-key",
        client=client,
      )
      with pytest.raises(ModelProviderError) as error:
        await model.propose({"question": "test"}, max_output_tokens=100)

    assert error.value.failure_code == "invalid_investigation_decision_json"


@pytest.mark.asyncio
async def test_gemini_adapter_rejects_empty_or_blocked_candidates():
  for candidate, expected_code in (
    (
      {"finishReason": "STOP", "content": {"parts": []}},
      "invalid_provider_decision_shape",
    ),
    (
      {"finishReason": "SAFETY", "content": {"parts": []}},
      "gemini_finish_safety",
    ),
  ):
    async def handler(_request: httpx.Request) -> httpx.Response:
      return httpx.Response(
        200,
        json={
          "candidates": [candidate],
          "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 0,
            "totalTokenCount": 10,
          },
        },
      )

    async with httpx.AsyncClient(
      transport=httpx.MockTransport(handler),
    ) as client:
      model = GeminiInvestigationModel(
        api_key="synthetic-api-key",
        client=client,
      )
      with pytest.raises(ModelProviderError) as error:
        await model.propose({"question": "test"}, max_output_tokens=100)

    assert error.value.failure_code == expected_code


@pytest.mark.asyncio
async def test_gemini_adapter_accepts_a_read_only_tool_decision():
  decision = {
    "action": "tool",
    "tool_name": "logs.query",
    "arguments": {"query": "synthetic error"},
    "claim": None,
    "evidence_ids": [],
  }

  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json=_decision_response(
        decision,
        usage={
          "promptTokenCount": 10,
          "candidatesTokenCount": 5,
          "totalTokenCount": 15,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    result = await model.propose(
      {"question": "test"},
      max_output_tokens=100,
    )

  assert result.decision.action == "tool"
  assert result.decision.tool_name == "logs.query"
  assert result.decision.arguments == {"query": "synthetic error"}


@pytest.mark.asyncio
async def test_gemini_adapter_rejects_token_usage_that_cannot_be_reconciled():
  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
      200,
      json=_decision_response(
        _conclusion("7c3e91a4-b620-4f20-9e45-c29db040f056"),
        usage={
          "promptTokenCount": 100,
          "candidatesTokenCount": 24,
          "totalTokenCount": 10,
        },
      ),
    )

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    model = GeminiInvestigationModel(
      api_key="synthetic-api-key",
      client=client,
    )
    with pytest.raises(ModelProviderError, match="invalid investigation token usage"):
      await model.propose({"question": "test"}, max_output_tokens=100)
