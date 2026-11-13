from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class InvestigationBudget(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  max_cycles: int = Field(ge=1, le=32)
  max_model_calls: int = Field(ge=1, le=32)
  max_model_tokens: int = Field(ge=1, le=100_000)
  max_tool_calls: int = Field(ge=0, le=64)
  max_duration_seconds: float = Field(gt=0, le=900)
  max_step_seconds: float = Field(gt=0, le=120)
  max_output_tokens_per_call: int = Field(ge=1, le=8192)


class InvestigationEvidence(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  id: uuid.UUID
  evidence_type: str = Field(min_length=1, max_length=128)
  provenance: str = Field(min_length=1, max_length=512)
  content: dict[str, Any]


class ReadOnlyToolResult(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  status: Literal["success", "empty", "partial", "unavailable", "error"]
  evidence: list[InvestigationEvidence] = Field(default_factory=list, max_length=64)
  error_code: str | None = Field(default=None, max_length=64)


class InvestigationDecision(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  action: Literal["tool", "conclude", "inconclusive"]
  tool_name: str | None = Field(default=None, min_length=1, max_length=128)
  arguments: dict[str, Any] = Field(default_factory=dict)
  claim: str | None = Field(default=None, max_length=1000)
  evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=16)

  @model_validator(mode="after")
  def validate_action_fields(self) -> InvestigationDecision:
    if self.action == "tool":
      if self.tool_name is None or self.claim is not None or self.evidence_ids:
        raise ValueError("A tool action requires only a tool name and arguments.")
    elif self.action == "conclude":
      if (
        self.claim is None
        or not self.claim.strip()
        or self.tool_name is not None
        or self.arguments
      ):
        raise ValueError("A conclusion requires a claim and no tool request.")
    elif (
      self.tool_name is not None
      or self.arguments
      or self.claim is not None
      or self.evidence_ids
    ):
      raise ValueError("An inconclusive action cannot include a tool or claim.")
    if len(set(self.evidence_ids)) != len(self.evidence_ids):
      raise ValueError("Evidence citations must be unique.")
    return self


class InvestigationModelResponse(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  decision: InvestigationDecision
  input_tokens: int = Field(ge=0)
  output_tokens: int = Field(ge=0)


class ReadOnlyToolDescriptor(BaseModel):
  model_config = ConfigDict(extra="forbid", strict=True)

  name: str = Field(min_length=1, max_length=128)
  description: str = Field(min_length=1, max_length=500)
  input_schema: dict[str, Any]
  read_only: Literal[True] = True


class ModelProviderError(Exception):
  pass


class ReadOnlyToolError(Exception):
  pass


class InvestigationModel(Protocol):
  def count_input_tokens(self, payload: dict[str, Any]) -> int: ...

  async def propose(
    self,
    payload: dict[str, Any],
    *,
    max_output_tokens: int,
  ) -> InvestigationModelResponse | dict[str, Any]: ...


ToolHandler = Callable[[dict[str, Any]], Awaitable[ReadOnlyToolResult | dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class ReadOnlyToolBinding:
  name: str
  description: str
  input_model: type[BaseModel]
  handler: ToolHandler
  read_only: bool = True

  def descriptor(self) -> ReadOnlyToolDescriptor:
    if not self.read_only:
      raise ValueError(f"Investigation tool {self.name!r} is not read-only.")
    return ReadOnlyToolDescriptor(
      name=self.name,
      description=self.description,
      input_schema=self.input_model.model_json_schema(mode="validation"),
      read_only=True,
    )


class InvestigationGraphState(TypedDict, total=False):
  run_id: str
  incident_id: str
  question: str
  budget: dict[str, int | float]
  evidence: list[dict[str, Any]]
  initial_evidence_truncated: bool
  tools: list[dict[str, Any]]
  cycle_count: int
  model_call_count: int
  model_tokens_consumed: int
  model_tokens_reserved: int
  tool_call_count: int
  deadline_epoch_seconds: float
  reserved_input_tokens: int
  reserved_output_tokens: int
  decision: dict[str, Any]
  pending_tool_name: str
  pending_tool_arguments: dict[str, Any]
  outcome: Literal["conclusion", "inconclusive", "failed"]
  claim: str | None
  evidence_citations: list[str]
  stop_reason: str
  terminal: bool
  tool_failures: list[dict[str, str]]
  interrupted: bool


def create_investigation_state(
  *,
  run_id: uuid.UUID,
  incident_id: uuid.UUID,
  question: str,
  evidence: Sequence[InvestigationEvidence],
  tools: Sequence[ReadOnlyToolBinding],
  budget: InvestigationBudget,
  initial_evidence_truncated: bool = False,
  deadline_epoch_seconds: float | None = None,
  clock: Callable[[], float] = time.time,
) -> InvestigationGraphState:
  if not question.strip():
    raise ValueError("Investigation question must not be blank.")
  tool_names = [tool.name for tool in tools]
  if len(set(tool_names)) != len(tool_names):
    raise ValueError("Investigation tool names must be unique.")
  descriptors = [tool.descriptor().model_dump(mode="json") for tool in tools]
  evidence_rows = [item.model_dump(mode="json") for item in evidence]
  evidence_ids = [item["id"] for item in evidence_rows]
  if len(set(evidence_ids)) != len(evidence_ids):
    raise ValueError("Initial evidence IDs must be unique.")
  return InvestigationGraphState(
    run_id=str(run_id),
    incident_id=str(incident_id),
    question=question,
    budget=budget.model_dump(mode="python"),
    evidence=evidence_rows,
    initial_evidence_truncated=initial_evidence_truncated,
    tools=descriptors,
    cycle_count=0,
    model_call_count=0,
    model_tokens_consumed=0,
    model_tokens_reserved=0,
    tool_call_count=0,
    deadline_epoch_seconds=(
      deadline_epoch_seconds
      if deadline_epoch_seconds is not None
      else clock() + budget.max_duration_seconds
    ),
    tool_failures=[],
    terminal=False,
  )


def _model_input(state: InvestigationGraphState) -> dict[str, Any]:
  return {
    "incident_id": state["incident_id"],
    "question": state["question"],
    "evidence": state["evidence"],
    "initial_evidence_truncated": state["initial_evidence_truncated"],
    "read_only_tools": state["tools"],
  }


def _parse_decision(value: dict[str, Any]) -> InvestigationDecision:
  return InvestigationDecision.model_validate_json(json.dumps(value))


def _parse_tool_result(value: ReadOnlyToolResult | dict[str, Any]) -> ReadOnlyToolResult:
  payload = (
    value.model_dump(mode="json")
    if isinstance(value, ReadOnlyToolResult)
    else value
  )
  return ReadOnlyToolResult.model_validate_json(json.dumps(payload))


def _remaining_seconds(
  state: InvestigationGraphState,
  clock: Callable[[], float],
) -> float:
  return state["deadline_epoch_seconds"] - clock()


def _stop(
  state: InvestigationGraphState,
  outcome: Literal["inconclusive", "failed"],
  reason: str,
) -> dict[str, Any]:
  return {
    "outcome": outcome,
    "claim": None,
    "evidence_citations": [],
    "stop_reason": reason,
    "terminal": True,
    "tool_failures": state.get("tool_failures", []),
  }


def compile_investigation_graph(
  *,
  model: InvestigationModel,
  tools: Sequence[ReadOnlyToolBinding],
  budget: InvestigationBudget,
  checkpointer: BaseCheckpointSaver | None = None,
  clock: Callable[[], float] = time.time,
  interrupt_before: Sequence[str] = (),
  interrupt_after: Sequence[str] = (),
):
  bindings = {tool.name: tool for tool in tools}
  if len(bindings) != len(tools):
    raise ValueError("Investigation tool names must be unique.")
  descriptors = [tool.descriptor().model_dump(mode="json") for tool in tools]

  expected_budget = budget.model_dump(mode="python")

  def configuration_matches(state: InvestigationGraphState) -> bool:
    return (
      state.get("budget") == expected_budget
      and state.get("tools") == descriptors
      and type(state.get("model_tokens_consumed")) is int
      and state["model_tokens_consumed"] >= 0
      and type(state.get("model_tokens_reserved")) is int
      and state["model_tokens_reserved"] >= 0
    )

  def reserve_cycle(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    if _remaining_seconds(state, clock) <= 0:
      return _stop(state, "inconclusive", "time_budget_exhausted")
    if state["cycle_count"] >= budget.max_cycles:
      return _stop(state, "inconclusive", "cycle_budget_exhausted")
    return {"cycle_count": state["cycle_count"] + 1}

  def reserve_model(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    if _remaining_seconds(state, clock) <= 0:
      return _stop(state, "inconclusive", "time_budget_exhausted")
    if state["model_call_count"] >= budget.max_model_calls:
      return _stop(state, "inconclusive", "model_call_budget_exhausted")
    try:
      input_tokens = model.count_input_tokens(_model_input(state))
    except (TypeError, ValueError):
      return _stop(state, "failed", "invalid_model_token_count")
    if (
      isinstance(input_tokens, bool)
      or not isinstance(input_tokens, int)
      or input_tokens < 0
    ):
      return _stop(state, "failed", "invalid_model_token_count")
    remaining_tokens = (
      budget.max_model_tokens
      - state["model_tokens_consumed"]
      - state["model_tokens_reserved"]
    )
    output_tokens = min(
      budget.max_output_tokens_per_call,
      remaining_tokens - input_tokens,
    )
    if output_tokens < 1:
      return _stop(state, "inconclusive", "model_token_budget_exhausted")
    return {
      "model_call_count": state["model_call_count"] + 1,
      "model_tokens_reserved": input_tokens + output_tokens,
      "reserved_input_tokens": input_tokens,
      "reserved_output_tokens": output_tokens,
    }

  async def call_model(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    remaining = _remaining_seconds(state, clock)
    if remaining <= 0:
      return _stop(state, "inconclusive", "time_budget_exhausted")
    try:
      async with asyncio.timeout(min(budget.max_step_seconds, remaining)):
        raw_response = await model.propose(
          _model_input(state),
          max_output_tokens=state["reserved_output_tokens"],
        )
    except TimeoutError:
      return _stop(state, "failed", "model_timeout")
    except ModelProviderError:
      return _stop(state, "failed", "model_provider_failure")
    try:
      response_payload = (
        raw_response.model_dump(mode="json")
        if isinstance(raw_response, InvestigationModelResponse)
        else raw_response
      )
      response = InvestigationModelResponse.model_validate_json(
        json.dumps(response_payload),
      )
    except (ValidationError, TypeError, ValueError):
      return _stop(state, "failed", "malformed_model_response")
    actual_tokens = response.input_tokens + response.output_tokens
    usage_update = {
      "model_tokens_consumed": state["model_tokens_consumed"] + actual_tokens,
      "model_tokens_reserved": 0,
      "reserved_input_tokens": 0,
      "reserved_output_tokens": 0,
    }
    if (
      response.input_tokens > state["reserved_input_tokens"]
      or response.output_tokens > state["reserved_output_tokens"]
      or state["model_tokens_consumed"] + actual_tokens > budget.max_model_tokens
    ):
      return {
        **_stop(state, "failed", "model_token_limit_exceeded"),
        **usage_update,
      }
    decision = response.decision
    if decision.action == "conclude":
      available_ids = {row["id"] for row in state["evidence"]}
      cited_ids = {str(item) for item in decision.evidence_ids}
      if not cited_ids.issubset(available_ids):
        return _stop(state, "failed", "unsupported_evidence_citation")
    return {
      **usage_update,
      "decision": decision.model_dump(mode="json"),
    }

  def route_after_reserve_cycle(state: InvestigationGraphState) -> str:
    return END if state.get("terminal") else "reserve_model"

  def route_after_reserve_model(state: InvestigationGraphState) -> str:
    return END if state.get("terminal") else "call_model"

  def route_after_model(state: InvestigationGraphState) -> str:
    if state.get("terminal"):
      return END
    decision = _parse_decision(state["decision"])
    if decision.action == "tool":
      return "reserve_tool"
    return "finish"

  def reserve_tool(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    decision = _parse_decision(state["decision"])
    if state["tool_call_count"] >= budget.max_tool_calls:
      return _stop(state, "inconclusive", "tool_call_budget_exhausted")
    reservation = {"tool_call_count": state["tool_call_count"] + 1}
    if _remaining_seconds(state, clock) <= 0:
      return {
        **_stop(state, "inconclusive", "time_budget_exhausted"),
        **reservation,
      }
    binding = bindings.get(decision.tool_name or "")
    if binding is None:
      return {
        **_stop(state, "failed", "tool_not_authorized"),
        **reservation,
      }
    try:
      validated = binding.input_model.model_validate(
        decision.arguments,
        strict=True,
        extra="forbid",
      )
    except ValidationError:
      return {
        **_stop(state, "failed", "invalid_tool_arguments"),
        **reservation,
      }
    return {
      **reservation,
      "pending_tool_name": binding.name,
      "pending_tool_arguments": validated.model_dump(mode="json"),
    }

  async def execute_tool(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    remaining = _remaining_seconds(state, clock)
    if remaining <= 0:
      return _stop(state, "inconclusive", "time_budget_exhausted")
    binding = bindings[state["pending_tool_name"]]
    try:
      async with asyncio.timeout(min(budget.max_step_seconds, remaining)):
        raw_result = await binding.handler(state["pending_tool_arguments"])
    except TimeoutError:
      failures = state["tool_failures"] + [{
        "tool_name": binding.name,
        "failure_code": "tool_timeout",
      }]
      return {
        "tool_failures": failures,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      }
    except ReadOnlyToolError as error:
      failures = state["tool_failures"] + [{
        "tool_name": binding.name,
        "failure_code": str(error)[:64] or "tool_failure",
      }]
      return {
        "tool_failures": failures,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      }
    try:
      result = _parse_tool_result(raw_result)
    except ValidationError:
      failures = state["tool_failures"] + [{
        "tool_name": binding.name,
        "failure_code": "malformed_tool_response",
      }]
      return {
        "tool_failures": failures,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      }

    evidence_rows = [item.model_dump(mode="json") for item in result.evidence]
    if result.status not in {"success", "partial"} and evidence_rows:
      failures = state["tool_failures"] + [{
        "tool_name": binding.name,
        "failure_code": "evidence_from_non_successful_tool",
      }]
      evidence_rows = []
      return {
        "tool_failures": failures,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      }
    existing_ids = {row["id"] for row in state["evidence"]}
    new_ids = [row["id"] for row in evidence_rows]
    if len(set(new_ids)) != len(new_ids) or existing_ids.intersection(new_ids):
      failures = state["tool_failures"] + [{
        "tool_name": binding.name,
        "failure_code": "duplicate_evidence_id",
      }]
      evidence_rows = []
      return {
        "tool_failures": failures,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      }

    failures = state["tool_failures"]
    if result.status in {"unavailable", "error"}:
      failures = failures + [{
        "tool_name": binding.name,
        "failure_code": result.error_code or result.status,
      }]
    return {
      "evidence": state["evidence"] + evidence_rows,
      "tool_failures": failures,
      "pending_tool_name": "",
      "pending_tool_arguments": {},
    }

  def route_after_tool(state: InvestigationGraphState) -> str:
    return END if state.get("terminal") else "reserve_cycle"

  def finish(state: InvestigationGraphState) -> dict[str, Any]:
    if not configuration_matches(state):
      return _stop(state, "failed", "run_configuration_changed")
    decision = _parse_decision(state["decision"])
    if decision.action == "inconclusive":
      return {
        **_stop(state, "inconclusive", "model_abstained"),
        "tool_failures": state["tool_failures"],
      }
    available_ids = {row["id"] for row in state["evidence"]}
    cited_ids = [str(item) for item in decision.evidence_ids]
    if not set(cited_ids).issubset(available_ids):
      return _stop(state, "failed", "unsupported_evidence_citation")
    if not cited_ids:
      return _stop(state, "failed", "conclusion_without_evidence")
    return {
      "outcome": "conclusion",
      "claim": decision.claim,
      "evidence_citations": cited_ids,
      "stop_reason": "conclusion_reached",
      "terminal": True,
      "tool_failures": state["tool_failures"],
    }

  workflow = StateGraph(InvestigationGraphState)
  workflow.add_node("reserve_cycle", reserve_cycle)
  workflow.add_node("reserve_model", reserve_model)
  workflow.add_node("call_model", call_model)
  workflow.add_node("reserve_tool", reserve_tool)
  workflow.add_node("execute_tool", execute_tool)
  workflow.add_node("finish", finish)
  workflow.add_edge(START, "reserve_cycle")
  workflow.add_conditional_edges(
    "reserve_cycle",
    route_after_reserve_cycle,
    {"reserve_model": "reserve_model", END: END},
  )
  workflow.add_conditional_edges(
    "reserve_model",
    route_after_reserve_model,
    {"call_model": "call_model", END: END},
  )
  workflow.add_conditional_edges(
    "call_model",
    route_after_model,
    {"reserve_tool": "reserve_tool", "finish": "finish", END: END},
  )
  workflow.add_conditional_edges(
    "reserve_tool",
    lambda state: END if state.get("terminal") else "execute_tool",
    {"execute_tool": "execute_tool", END: END},
  )
  workflow.add_conditional_edges(
    "execute_tool",
    route_after_tool,
    {"reserve_cycle": "reserve_cycle", END: END},
  )
  workflow.add_edge("finish", END)
  return workflow.compile(
    checkpointer=checkpointer,
    interrupt_before=list(interrupt_before),
    interrupt_after=list(interrupt_after),
  )


def investigation_graph_config(run_id: uuid.UUID) -> dict[str, Any]:
  return {"configurable": {"thread_id": str(run_id)}}


async def resume_investigation_graph(
  graph: Any,
  run_id: uuid.UUID,
) -> InvestigationGraphState:
  config = investigation_graph_config(run_id)
  snapshot = await graph.aget_state(config)
  if not snapshot.values:
    raise ValueError(f"No checkpoint exists for investigation run {run_id}.")
  pending = set(snapshot.next)
  unsafe_resume_nodes = pending.intersection({"call_model", "execute_tool"})
  if unsafe_resume_nodes:
    node_name = sorted(unsafe_resume_nodes)[0]
    await graph.aupdate_state(
      config,
      {
        "outcome": "failed",
        "claim": None,
        "evidence_citations": [],
        "stop_reason": "interrupted_external_operation",
        "terminal": True,
        "pending_tool_name": "",
        "pending_tool_arguments": {},
      },
      as_node=node_name,
    )
  return await graph.ainvoke(None, config)
