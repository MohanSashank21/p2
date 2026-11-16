from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ValidationError

from app.services.incident_service import get_project_incident
from app.tools.contracts import (
  ToolContext,
  ToolDefinition,
  ToolDescriptor,
  ToolError,
  ToolNotFoundError,
  ToolResult,
)


class ToolRegistry:
  def __init__(self, tools: Iterable[ToolDefinition[Any]] = ()):
    self._tools: dict[str, ToolDefinition[Any]] = {}
    for tool in tools:
      self.register(tool)

  def register(self, tool: ToolDefinition[Any]) -> None:
    if not tool.name.strip() or not tool.description.strip():
      raise ValueError("Tool name and description must not be blank")
    if not tool.read_only:
      raise ValueError("Only read-only tools can be registered")
    if tool.name in self._tools:
      raise ValueError(f"Duplicate tool name: {tool.name}")
    self._tools[tool.name] = tool

  def list_tools(self) -> list[ToolDescriptor]:
    return [
      ToolDescriptor(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_model.model_json_schema(mode="validation"),
        output_schema=ToolResult.model_json_schema(mode="serialization"),
        read_only=tool.read_only,
        persists_evidence=tool.persists_evidence,
      )
      for tool in sorted(self._tools.values(), key=lambda item: item.name)
    ]

  def get_tool_definitions(self) -> tuple[ToolDefinition[Any], ...]:
    return tuple(
      sorted(self._tools.values(), key=lambda item: item.name)
    )

  async def execute(
    self,
    name: str,
    arguments: dict[str, Any],
    context: ToolContext,
  ) -> ToolResult:
    await get_project_incident(
      context.session,
      context.project_id,
      context.incident_id,
      context.user,
    )
    tool = self._tools.get(name)
    if tool is None:
      raise ToolNotFoundError(f"Tool not found: {name}")
    try:
      parsed_arguments: BaseModel = tool.input_model.model_validate(
        arguments,
        extra="forbid",
      )
    except ValidationError:
      return ToolResult(
        status="error",
        error=ToolError(
          code="invalid_arguments",
          message="Tool arguments did not match the declared input schema.",
        ),
      )
    return await tool.handler(context, parsed_arguments)


def create_tool_registry(
  *,
  include_internet_search: bool = True,
) -> ToolRegistry:
  from app.tools.docker import investigate_incident_container_tool
  from app.tools.github import investigate_github_workflow_tool
  from app.tools.incident_evidence import read_incident_evidence_tool
  from app.tools.loki import query_incident_logs_tool
  from app.tools.prometheus import (
    query_prometheus_instant_tool,
    query_prometheus_range_tool,
  )
  from app.tools.tempo import query_incident_traces_tool

  tools = [
    investigate_incident_container_tool,
    investigate_github_workflow_tool,
    read_incident_evidence_tool,
    query_incident_logs_tool,
    query_prometheus_instant_tool,
    query_prometheus_range_tool,
    query_incident_traces_tool,
  ]
  if include_internet_search:
    from app.core.config import settings
    if settings.GEMINI_WEB_SEARCH_ENABLED:
      from app.tools.internet_search import internet_search_tool

      tools.append(internet_search_tool)
  return ToolRegistry(tools)
