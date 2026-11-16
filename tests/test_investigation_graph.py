from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import NodeCancelledError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.services.investigation_graph import (
  InvestigationBudget,
  InvestigationDecision,
  InvestigationEvidence,
  InvestigationModelResponse,
  ModelProviderError,
  ReadOnlyToolBinding,
  ReadOnlyToolError,
  ReadOnlyToolResult,
  compile_investigation_graph,
  create_investigation_state,
  investigation_graph_config,
  resume_investigation_graph,
)
from scripts.incident_benchmark_data import SCENARIOS
from scripts.investigation_benchmark import (
  InvestigationBudget as BenchmarkBudget,
  InvestigationRunTrace,
  evaluate_scenarios,
)


class QueryArguments(BaseModel):
  model_config = ConfigDict(extra="forbid")

  query: str = Field(min_length=1, max_length=100)


class ScriptedModel:
  def __init__(
    self,
    script: list[Any],
    *,
    token_counter: Callable[[dict[str, Any]], int] | None = None,
  ) -> None:
    self.script = list(script)
    self.token_counter = token_counter or (
      lambda payload: len(json.dumps(payload, sort_keys=True))
    )
    self.calls: list[dict[str, Any]] = []
    self.output_limits: list[int] = []

  async def count_input_tokens(self, payload: dict[str, Any]) -> int:
    return self.token_counter(payload)

  async def propose(
    self,
    payload: dict[str, Any],
    *,
    max_output_tokens: int,
  ) -> InvestigationModelResponse | dict[str, Any]:
    self.calls.append(payload)
    self.output_limits.append(max_output_tokens)
    if not self.script:
      raise AssertionError("Scripted model was called more times than configured.")
    response = self.script.pop(0)
    if isinstance(response, BaseException):
      raise response
    if callable(response):
      response = response(
        payload,
        max_output_tokens=max_output_tokens,
      )
      if asyncio.iscoroutine(response):
        response = await response
    if isinstance(response, InvestigationModelResponse):
      response = response.model_copy(
        update={"input_tokens": await self.count_input_tokens(payload)},
      )
    return response


def _evidence(content: dict[str, Any], provenance: str = "fixture://incident") -> InvestigationEvidence:
  return InvestigationEvidence(
    id=uuid.uuid4(),
    evidence_type="synthetic_observation",
    provenance=provenance,
    content=content,
  )


def _tool_result(
  evidence: list[InvestigationEvidence] | None = None,
) -> ReadOnlyToolResult:
  return ReadOnlyToolResult(status="success", evidence=evidence or [])


def _binding(handler: Callable[..., Any]) -> ReadOnlyToolBinding:
  return ReadOnlyToolBinding(
    name="logs.query",
    description="Read incident logs.",
    input_model=QueryArguments,
    handler=handler,
  )


def _budget(**overrides: Any) -> InvestigationBudget:
  values = {
    "max_cycles": 4,
    "max_model_calls": 4,
    "max_model_tokens": 20_000,
    "max_tool_calls": 4,
    "max_output_tokens_per_call": 100,
  }
  values.update(overrides)
  return InvestigationBudget(**values)


def _state(
  *,
  evidence: list[InvestigationEvidence] | None = None,
  tools: tuple[ReadOnlyToolBinding, ...] = (),
  budget: InvestigationBudget | None = None,
) -> dict[str, Any]:
  return create_investigation_state(
    run_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    question="Why did the synthetic incident occur?",
    evidence=evidence or [],
    tools=tools,
    budget=budget or _budget(),
  )


def _response(
  decision: InvestigationDecision,
  output_tokens: int = 1,
) -> InvestigationModelResponse:
  return InvestigationModelResponse(
    decision=decision,
    input_tokens=0,
    output_tokens=output_tokens,
  )


async def _run(
  model: ScriptedModel,
  *,
  state: dict[str, Any] | None = None,
  tools: tuple[ReadOnlyToolBinding, ...] = (),
  budget: InvestigationBudget | None = None,
  checkpointer: InMemorySaver | None = None,
  interrupt_before: tuple[str, ...] = (),
  interrupt_after: tuple[str, ...] = (),
) -> dict[str, Any]:
  current_budget = budget or _budget()
  graph = compile_investigation_graph(
    model=model,
    tools=tools,
    budget=current_budget,
    checkpointer=checkpointer,
    interrupt_before=interrupt_before,
    interrupt_after=interrupt_after,
  )
  initial_state = state or _state(
    tools=tools,
    budget=current_budget,
  )
  run_id = uuid.UUID(initial_state["run_id"])
  return await graph.ainvoke(
    initial_state,
    investigation_graph_config(run_id),
  )


@pytest.mark.asyncio
async def test_loop_concludes_only_with_server_known_evidence_ids():
  evidence = _evidence({"observation": "the service restarted"})
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="conclude",
      claim="The service restarted.",
      evidence_ids=[evidence.id],
    )),
  ])

  result = await _run(model, state=_state(evidence=[evidence]))

  assert result["outcome"] == "conclusion"
  assert result["evidence_citations"] == [str(evidence.id)]
  assert result["model_call_count"] == 1
  assert result["provider_attempt_count"] == 2
  assert result["model_tokens_consumed"] > 0
  assert result["model_tokens_reserved"] == 0


def test_conclusion_requires_at_least_one_evidence_citation():
  with pytest.raises(ValidationError, match="at least one evidence citation"):
    InvestigationDecision(
      action="conclude",
      claim="A claim without supporting evidence.",
    )


@pytest.mark.asyncio
async def test_unknown_model_citation_fails_closed():
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="conclude",
      claim="A fabricated cause.",
      evidence_ids=[uuid.uuid4()],
    )),
  ])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "unsupported_evidence_citation"
  assert result["evidence_citations"] == []


@pytest.mark.asyncio
async def test_contradictory_evidence_can_be_reported_as_inconclusive():
  evidence = [
    _evidence({"status": "healthy", "observed_at": "12:00"}),
    _evidence({"status": "unhealthy", "observed_at": "12:01"}),
  ]
  model = ScriptedModel([
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(model, state=_state(evidence=evidence))

  assert result["outcome"] == "inconclusive"
  assert result["stop_reason"] == "model_abstained"
  assert len(model.calls[0]["evidence"]) == 2
  assert result["evidence_citations"] == []


@pytest.mark.asyncio
async def test_malformed_tool_response_is_discarded_and_loop_can_abstain():
  calls = 0

  async def malformed_tool(_arguments: dict[str, Any]) -> dict[str, Any]:
    nonlocal calls
    calls += 1
    return {
      "status": "success",
      "evidence": [{"id": str(uuid.uuid4()), "content": {"fake": True}}],
    }

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])
  tool = _binding(malformed_tool)

  result = await _run(model, tools=(tool,))

  assert result["outcome"] == "inconclusive"
  assert result["tool_call_count"] == 1
  assert result["evidence"] == []
  assert result["tool_failures"] == [{
    "tool_name": "logs.query",
    "failure_code": "malformed_tool_response",
  }]
  assert calls == 1


@pytest.mark.asyncio
async def test_failed_tool_result_cannot_smuggle_evidence_into_model_context():
  failed_evidence = _evidence({"untrusted": "failure payload"})
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])
  tool = _binding(lambda _arguments: asyncio.sleep(0, result=ReadOnlyToolResult(
    status="unavailable",
    evidence=[failed_evidence],
    error_code="provider_down",
  )))

  result = await _run(model, tools=(tool,))

  assert result["outcome"] == "inconclusive"
  assert all(row["id"] != str(failed_evidence.id) for row in result["evidence"])
  assert all(row["id"] != str(failed_evidence.id) for row in model.calls[1]["evidence"])
  assert result["tool_failures"][0]["failure_code"] == (
    "evidence_from_non_successful_tool"
  )


@pytest.mark.asyncio
async def test_tool_can_reuse_identical_incident_evidence_without_duplicating_it():
  evidence = _evidence({"observation": "the workflow failed at build"})
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "workflow failure"},
    )),
    _response(InvestigationDecision(
      action="conclude",
      claim="The workflow failed at build.",
      evidence_ids=[evidence.id],
    )),
  ])
  tool = _binding(lambda _arguments: asyncio.sleep(
    0,
    result=_tool_result([evidence]),
  ))

  result = await _run(
    model,
    state=_state(evidence=[evidence], tools=(tool,)),
    tools=(tool,),
  )

  assert result["outcome"] == "conclusion", {
    key: result.get(key)
    for key in ("stop_reason", "failure_detail", "decision", "tool_failures")
  }
  assert result["evidence_citations"] == [str(evidence.id)]
  assert len(result["evidence"]) == 1
  assert result["tool_failures"] == []


@pytest.mark.asyncio
async def test_unauthorized_tool_request_never_executes():
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result()

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="shell.execute",
      arguments={"command": "ignored"},
    )),
  ])

  result = await _run(model, tools=(_binding(tool_handler),))

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "tool_not_authorized"
  assert result["tool_call_count"] == 1
  assert result["tool_failures"] == [{
    "tool_name": "shell.execute",
    "failure_code": "tool_not_authorized",
  }]
  assert calls == 0


@pytest.mark.asyncio
async def test_invalid_tool_arguments_never_execute():
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result()

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "", "unexpected": True},
    )),
  ])

  result = await _run(model, tools=(_binding(tool_handler),))

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "invalid_tool_arguments"
  assert result["tool_call_count"] == 1
  assert calls == 0


@pytest.mark.asyncio
async def test_strict_tool_validation_accepts_json_uuid_arguments():
  class GitHubArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_id: int
    event_id: uuid.UUID

  executed_arguments: list[dict[str, Any]] = []

  async def tool_handler(arguments: dict[str, Any]) -> ReadOnlyToolResult:
    executed_arguments.append(arguments)
    return _tool_result()

  tool = ReadOnlyToolBinding(
    name="github.investigate_failed_workflow",
    description="Read a failed workflow.",
    input_model=GitHubArguments,
    handler=tool_handler,
  )
  event_id = str(uuid.uuid4())
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name=tool.name,
      arguments={
        "repository_id": 1249219668,
        "event_id": event_id,
      },
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(model, tools=(tool,))

  assert result["outcome"] == "inconclusive"
  assert result["tool_call_count"] == 1
  assert executed_arguments == [{
    "repository_id": 1249219668,
    "event_id": event_id,
  }]


@pytest.mark.asyncio
async def test_model_provider_failure_stops_without_retry():
  model = ScriptedModel([ModelProviderError("synthetic outage")])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "model_provider_failure"
  assert result["model_call_count"] == 1
  assert result["model_tokens_consumed"] == 0
  assert result["model_tokens_reserved"] == 0
  assert result["model_tokens_unreconciled"] > 0
  assert len(model.calls) == 1


@pytest.mark.asyncio
async def test_model_provider_failure_preserves_safe_failure_code():
  model = ScriptedModel([
    ModelProviderError(
      "Provider rejected the generation request.",
      failure_code="gemini_invalid_request",
    ),
  ])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "gemini_invalid_request"
  assert result["model_tokens_consumed"] == 0
  assert result["model_tokens_reserved"] == 0
  assert result["model_tokens_unreconciled"] > 0


@pytest.mark.asyncio
async def test_invalid_decision_logs_run_correlated_safe_diagnostic(caplog):
  state = _state()
  model = ScriptedModel([
    ModelProviderError(
      "Gemini returned an invalid investigation decision; "
      "decision failed validation at: evidence_ids.0:invalid_value.",
      failure_code="invalid_investigation_decision",
      input_tokens=10,
      output_tokens=2,
    ),
  ])

  with caplog.at_level(
    logging.WARNING,
    logger="app.services.investigation_graph",
  ):
    result = await _run(model, state=state)

  diagnostic = next(
    record
    for record in caplog.records
    if record.getMessage()
    == "Gemini investigation decision failed schema validation"
  )
  assert diagnostic.investigation_run_id == state["run_id"]
  assert diagnostic.response_format == "application/json"
  assert diagnostic.response_schema == "investigation_decision"
  assert diagnostic.provider_http_status == 200
  assert diagnostic.candidate_finish_reason == "STOP"
  assert diagnostic.generation_attempt == 1
  assert diagnostic.provider_request_count == 2
  assert diagnostic.input_tokens == 10
  assert diagnostic.output_tokens == 2
  assert "evidence_ids.0:invalid_value" in diagnostic.validation_diagnostic
  assert result["failure_detail"] == (
    "Gemini returned an invalid investigation decision."
  )


@pytest.mark.asyncio
async def test_transient_provider_failure_retries_within_model_call_budget():
  model = ScriptedModel([
    ModelProviderError(
      "Gemini was rate limited.",
      failure_code="gemini_rate_limited",
      retryable=True,
      retry_after_seconds=0,
    ),
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(model)

  assert result["outcome"] == "inconclusive"
  assert result["model_call_count"] == 2
  assert result["provider_attempt_count"] == 3
  assert len(model.calls) == 2
  assert result["model_tokens_unreconciled"] > 0
  assert result["model_tokens_reserved"] == 0


@pytest.mark.asyncio
async def test_provider_retries_do_not_exceed_model_call_budget():
  model = ScriptedModel([
    ModelProviderError(
      "Gemini was rate limited.",
      failure_code="gemini_rate_limited",
      retryable=True,
      retry_after_seconds=0,
    )
    for _ in range(3)
  ])

  result = await _run(model, budget=_budget(max_model_calls=2))

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "gemini_rate_limited"
  assert result["model_call_count"] == 2
  assert result["provider_attempt_count"] == 3
  assert len(model.calls) == 2
  assert result["model_tokens_reserved"] == 0


@pytest.mark.asyncio
async def test_retry_after_is_honored_without_investigation_deadline(monkeypatch):
  model = ScriptedModel([
    ModelProviderError(
      "Gemini was rate limited.",
      failure_code="gemini_rate_limited",
      retryable=True,
      retry_after_seconds=5,
    ),
    _response(InvestigationDecision(action="inconclusive")),
  ])

  delays: list[float] = []

  async def record_delay(delay: float) -> None:
    delays.append(delay)

  monkeypatch.setattr("app.services.investigation_graph.asyncio.sleep", record_delay)

  result = await _run(model)

  assert result["outcome"] == "inconclusive"
  assert result["model_call_count"] == 2
  assert len(model.calls) == 2
  assert delays == [5]
  assert result["model_tokens_reserved"] == 0
  assert result["model_tokens_unreconciled"] > 0


@pytest.mark.asyncio
async def test_provider_failure_with_usage_reconciles_tokens():
  model = ScriptedModel([
    ModelProviderError(
      "Gemini returned a malformed decision.",
      failure_code="invalid_investigation_decision",
      input_tokens=8,
      output_tokens=2,
    ),
  ])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["model_tokens_consumed"] == 10
  assert result["model_tokens_unreconciled"] == 0
  assert result["model_tokens_reserved"] == 0


@pytest.mark.asyncio
async def test_model_call_can_exceed_old_investigation_timeout_values():
  async def slow_model(
    _payload: dict[str, Any],
    *,
    max_output_tokens: int,
  ) -> InvestigationModelResponse:
    await asyncio.sleep(0.05)
    return _response(
      InvestigationDecision(action="inconclusive"),
      max_output_tokens,
    )

  model = ScriptedModel([slow_model])

  result = await _run(model)

  assert result["outcome"] == "inconclusive"
  assert result["model_call_count"] == 1
  assert result["model_tokens_reserved"] == 0
  assert result["model_tokens_consumed"] > 0
  assert len(model.calls) == 1


@pytest.mark.asyncio
async def test_malformed_model_response_is_not_retried():
  model = ScriptedModel([{
    "decision": {"action": "conclude", "claim": "No citations."},
    "output_tokens": "not-an-integer",
  }])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "malformed_model_response"
  assert result["model_call_count"] == 1
  assert result["model_tokens_reserved"] == 0
  assert result["model_tokens_unreconciled"] > 0
  assert len(model.calls) == 1


@pytest.mark.asyncio
async def test_unserializable_model_response_fails_closed():
  model = ScriptedModel([object()])

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "malformed_model_response"
  assert result["model_call_count"] == 1
  assert len(model.calls) == 1


@pytest.mark.asyncio
async def test_tool_call_can_complete_without_graph_timeout():
  calls = 0
  tool_evidence = _evidence({"observation": "tool completed"})

  async def slow_tool(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    await asyncio.sleep(0.05)
    return _tool_result([tool_evidence])

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(
    model,
    tools=(_binding(slow_tool),),
  )

  assert result["outcome"] == "inconclusive"
  assert result["tool_call_count"] == 1
  assert calls == 1
  assert [row["id"] for row in result["evidence"]] == [str(tool_evidence.id)]
  assert result["tool_failures"] == []


@pytest.mark.asyncio
async def test_tool_provider_failure_is_contained_without_retry():
  calls = 0

  async def failing_tool(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    raise ReadOnlyToolError("provider unavailable")

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(model, tools=(_binding(failing_tool),))

  assert result["outcome"] == "inconclusive"
  assert result["tool_call_count"] == 1
  assert calls == 1
  assert result["evidence"] == []
  assert result["tool_failures"][0]["failure_code"] == "provider unavailable"


@pytest.mark.asyncio
async def test_repeated_tool_requests_cannot_exceed_central_budget():
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result()

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "first"},
    )),
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "second"},
    )),
  ])

  result = await _run(
    model,
    tools=(_binding(tool_handler),),
    budget=_budget(max_tool_calls=1),
  )

  assert result["outcome"] == "inconclusive"
  assert result["stop_reason"] == "tool_call_budget_exhausted"
  assert result["tool_call_count"] == 1
  assert calls == 1
  assert result["model_call_count"] == 2


@pytest.mark.asyncio
async def test_iteration_and_model_call_limits_are_shared_across_cycles():
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result()

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "first"},
    )),
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "second"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ])
  result = await _run(
    model,
    tools=(_binding(tool_handler),),
    budget=_budget(max_cycles=2, max_model_calls=2, max_tool_calls=3),
  )

  assert result["outcome"] == "inconclusive"
  assert result["stop_reason"] == "cycle_budget_exhausted"
  assert result["cycle_count"] == 2
  assert result["model_call_count"] == 2
  assert calls == 2
  assert len(model.calls) == 2


@pytest.mark.asyncio
async def test_state_does_not_store_a_wall_clock_deadline():
  evidence = _evidence({"observation": "persisted"})
  state = create_investigation_state(
    run_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    question="test persisted deadline",
    evidence=[evidence],
    tools=(),
    budget=_budget(),
  )
  assert "deadline_epoch_seconds" not in state


@pytest.mark.asyncio
async def test_resume_rejects_changed_budget_configuration():
  saver = InMemorySaver()
  model = ScriptedModel([
    _response(InvestigationDecision(action="inconclusive")),
  ])
  original_budget = _budget()
  state = _state(budget=original_budget)
  run_id = uuid.UUID(state["run_id"])
  original_graph = compile_investigation_graph(
    model=model,
    tools=(),
    budget=original_budget,
    checkpointer=saver,
    interrupt_after=("reserve_cycle",),
  )
  await original_graph.ainvoke(state, investigation_graph_config(run_id))

  resumed_graph = compile_investigation_graph(
    model=model,
    tools=(),
    budget=_budget(max_tool_calls=original_budget.max_tool_calls + 1),
    checkpointer=saver,
  )
  result = await resume_investigation_graph(resumed_graph, run_id)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "run_configuration_changed"
  assert len(model.calls) == 0


@pytest.mark.asyncio
async def test_interruption_during_tool_execution_is_not_replayed():
  saver = InMemorySaver()
  calls = 0

  async def interrupted_tool(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    raise asyncio.CancelledError

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
  ])
  tool = _binding(interrupted_tool)
  state = _state(tools=(tool,))
  run_id = uuid.UUID(state["run_id"])
  graph = compile_investigation_graph(
    model=model,
    tools=(tool,),
    budget=_budget(),
    checkpointer=saver,
  )

  with pytest.raises(NodeCancelledError):
    await graph.ainvoke(state, investigation_graph_config(run_id))
  assert calls == 1

  result = await resume_investigation_graph(graph, run_id)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "interrupted_external_operation"
  assert result["tool_call_count"] == 1
  assert calls == 1


@pytest.mark.asyncio
async def test_model_token_budget_is_reserved_before_call():
  model = ScriptedModel(
    [_response(InvestigationDecision(action="inconclusive"))],
    token_counter=lambda _payload: 9,
  )
  budget = _budget(max_model_tokens=10, max_output_tokens_per_call=5)

  result = await _run(model, budget=budget)

  assert result["outcome"] == "inconclusive"
  assert result["model_tokens_consumed"] == 10
  assert result["model_tokens_reserved"] == 0
  assert model.output_limits == [1]


@pytest.mark.asyncio
async def test_invalid_input_token_count_fails_before_model_call():
  model = ScriptedModel(
    [_response(InvestigationDecision(action="inconclusive"))],
    token_counter=lambda _payload: 1.5,
  )

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "invalid_model_token_count"
  assert result["model_call_count"] == 0
  assert len(model.calls) == 0


@pytest.mark.asyncio
async def test_token_count_provider_failure_stops_before_generation():
  def fail_count(_payload: dict[str, Any]) -> int:
    raise ModelProviderError("synthetic token count outage")

  model = ScriptedModel(
    [_response(InvestigationDecision(action="inconclusive"))],
    token_counter=fail_count,
  )

  result = await _run(model)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "model_token_count_failure"
  assert result["model_call_count"] == 0
  assert len(model.calls) == 0


@pytest.mark.asyncio
async def test_transient_token_count_failure_retries_inside_step_budget():
  class RetryableTokenCountModel(ScriptedModel):
    count_calls = 0

    async def count_input_tokens(self, payload: dict[str, Any]) -> int:
      self.count_calls += 1
      if self.count_calls == 1:
        raise ModelProviderError(
          "Gemini token counting was rate limited.",
          failure_code="gemini_rate_limited",
          retryable=True,
          retry_after_seconds=0,
        )
      return await super().count_input_tokens(payload)

  model = RetryableTokenCountModel([
    _response(InvestigationDecision(action="inconclusive")),
  ])

  result = await _run(model)

  assert result["outcome"] == "inconclusive"
  assert model.count_calls == 3
  assert result["model_call_count"] == 1
  assert result["provider_attempt_count"] == 3
  assert len(model.calls) == 1


@pytest.mark.asyncio
async def test_model_cannot_exceed_reserved_output_token_limit():
  model = ScriptedModel([
    _response(InvestigationDecision(action="inconclusive"), output_tokens=2),
  ])
  budget = _budget(max_model_tokens=101, max_output_tokens_per_call=1)
  model.token_counter = lambda _payload: 100

  result = await _run(model, budget=budget)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "model_output_token_reservation_exceeded"
  assert result["model_tokens_consumed"] == 102
  assert result["model_tokens_reserved"] == 0


@pytest.mark.asyncio
async def test_actual_usage_is_reconciled_before_reserving_the_next_model_call():
  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "first"},
    )),
    _response(InvestigationDecision(action="inconclusive")),
  ], token_counter=lambda _payload: 4)
  tool = _binding(lambda _arguments: asyncio.sleep(0, result=_tool_result()))
  budget = _budget(
    max_model_tokens=10,
    max_output_tokens_per_call=5,
    max_model_calls=2,
  )

  result = await _run(model, tools=(tool,), budget=budget)

  assert result["outcome"] == "inconclusive"
  assert result["stop_reason"] == "model_abstained"
  assert result["model_tokens_consumed"] == 10
  assert result["model_tokens_reserved"] == 0
  assert result["model_call_count"] == 2
  assert model.output_limits == [5, 1]


@pytest.mark.asyncio
async def test_actual_input_usage_above_preflight_reservation_fails_closed():
  model = ScriptedModel([{
    "decision": {"action": "inconclusive"},
    "input_tokens": 11,
    "output_tokens": 1,
  }], token_counter=lambda _payload: 10)
  budget = _budget(max_model_tokens=20, max_output_tokens_per_call=10)

  result = await _run(model, budget=budget)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "model_input_token_reservation_exceeded"
  assert result["model_tokens_consumed"] == 12
  assert result["model_tokens_reserved"] == 0


@pytest.mark.asyncio
async def test_checkpoint_resumes_after_completed_tool_without_repeating_it():
  saver = InMemorySaver()
  tool_evidence = _evidence({"observation": "log line collected"})
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result([tool_evidence])

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
    lambda payload, **_kwargs: _response(InvestigationDecision(
      action="conclude",
      claim="The error is visible in the collected log.",
      evidence_ids=[uuid.UUID(payload["evidence"][-1]["id"])],
    )),
  ])
  tool = _binding(tool_handler)
  state = _state(tools=(tool,))
  run_id = uuid.UUID(state["run_id"])
  graph = compile_investigation_graph(
    model=model,
    tools=(tool,),
    budget=_budget(),
    checkpointer=saver,
    interrupt_after=("execute_tool",),
  )
  config = investigation_graph_config(run_id)

  interrupted = await graph.ainvoke(state, config)
  assert interrupted["evidence"][-1]["id"] == str(tool_evidence.id)
  assert calls == 1
  result = await resume_investigation_graph(graph, run_id)

  assert result["outcome"] == "conclusion"
  assert result["evidence_citations"] == [str(tool_evidence.id)]
  assert calls == 1
  assert result["tool_call_count"] == 1


@pytest.mark.asyncio
async def test_interrupted_tool_node_fails_closed_instead_of_replaying():
  saver = InMemorySaver()
  calls = 0

  async def tool_handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    nonlocal calls
    calls += 1
    return _tool_result()

  model = ScriptedModel([
    _response(InvestigationDecision(
      action="tool",
      tool_name="logs.query",
      arguments={"query": "errors"},
    )),
  ])
  tool = _binding(tool_handler)
  state = _state(tools=(tool,))
  run_id = uuid.UUID(state["run_id"])
  graph = compile_investigation_graph(
    model=model,
    tools=(tool,),
    budget=_budget(),
    checkpointer=saver,
    interrupt_before=("execute_tool",),
  )

  paused = await graph.ainvoke(state, investigation_graph_config(run_id))
  assert paused["tool_call_count"] == 1
  assert calls == 0
  result = await resume_investigation_graph(graph, run_id)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "interrupted_external_operation"
  assert calls == 0


@pytest.mark.asyncio
async def test_interrupted_model_node_fails_closed_instead_of_replaying():
  saver = InMemorySaver()
  model = ScriptedModel([
    _response(InvestigationDecision(action="inconclusive")),
  ])
  state = _state()
  run_id = uuid.UUID(state["run_id"])
  graph = compile_investigation_graph(
    model=model,
    tools=(),
    budget=_budget(),
    checkpointer=saver,
    interrupt_before=("call_model",),
  )

  paused = await graph.ainvoke(state, investigation_graph_config(run_id))
  assert paused["model_call_count"] == 1
  assert len(model.calls) == 0
  result = await resume_investigation_graph(graph, run_id)

  assert result["outcome"] == "failed"
  assert result["stop_reason"] == "interrupted_external_operation"
  assert result["model_call_count"] == 1
  assert result["model_tokens_consumed"] == 0
  assert result["model_tokens_reserved"] > 0
  assert len(model.calls) == 0


@pytest.mark.asyncio
async def test_non_read_only_tool_cannot_be_registered():
  async def handler(_arguments: dict[str, Any]) -> ReadOnlyToolResult:
    return _tool_result()

  tool = ReadOnlyToolBinding(
    name="repository.write",
    description="Mutating tool.",
    input_model=QueryArguments,
    handler=handler,
    read_only=False,
  )
  model = ScriptedModel([])

  with pytest.raises(ValueError, match="is not read-only"):
    compile_investigation_graph(
      model=model,
      tools=(tool,),
      budget=_budget(),
    )


def test_investigation_quality_metrics_are_separate_from_safety_invariants():
  traces = {
    scenario["id"]: InvestigationRunTrace(
      outcome="inconclusive",
      cycles=0,
      model_calls=0,
      model_tokens=0,
    )
    for scenario in SCENARIOS
  }
  report = evaluate_scenarios(
    traces,
    allowed_tool_names=set(),
    budget=BenchmarkBudget(
      max_cycles=1,
      max_model_calls=1,
      max_model_tokens=1,
      max_tool_calls=0,
    ),
  )

  assert report["safety_passed"] is True
  assert all(report["safety_invariants"].values())
  assert report["investigation_quality"]["abstention_accuracy"] == 8 / 13
  assert report["investigation_quality"]["root_cause_accuracy"] is None
  assert report["root_cause_accuracy"] is None
  assert report["live_provider_calls"] == 0
