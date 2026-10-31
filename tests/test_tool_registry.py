from collections.abc import Awaitable, Callable
import uuid
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel

from app.core.exceptions import PermissionDeniedError
from app.db.user import User
from app.tools.contracts import (
  ToolContext,
  ToolDefinition,
  ToolError,
  ToolResult,
)
from app.tools.registry import ToolRegistry


class EchoArguments(BaseModel):
  value: int


def _context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="tool-test@example.invalid",
      display_name="Tool Test",
      password_hash="not-a-real-password-hash",
    ),
  )


def _tool(
  name: str,
  handler: Callable[[ToolContext, EchoArguments], Awaitable[ToolResult]],
) -> ToolDefinition[EchoArguments]:
  return ToolDefinition(
    name=name,
    description=f"Test tool {name}",
    input_model=EchoArguments,
    handler=handler,
  )


def test_registry_rejects_duplicate_names_and_lists_stably():
  async def handler(_context: ToolContext, _arguments: EchoArguments):
    return ToolResult(status="success")

  registry = ToolRegistry((_tool("test.zeta", handler), _tool("test.alpha", handler)))

  assert [tool.name for tool in registry.list_tools()] == [
    "test.alpha",
    "test.zeta",
  ]
  assert registry.list_tools()[0].input_schema["properties"]["value"] == {
    "title": "Value",
    "type": "integer",
  }
  assert registry.list_tools()[0].read_only is True
  with pytest.raises(ValueError, match="Duplicate tool name"):
    registry.register(_tool("test.alpha", handler))
  with pytest.raises(ValueError, match="Only read-only"):
    registry.register(
      ToolDefinition(
        name="test.mutate",
        description="Mutating test tool",
        input_model=EchoArguments,
        handler=handler,
        read_only=False,
      ),
    )


@pytest.mark.asyncio
async def test_execute_validates_arguments_and_uses_authorized_context(monkeypatch):
  context = _context()
  authorization_check = AsyncMock()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    authorization_check,
  )
  received: list[tuple[ToolContext, EchoArguments]] = []

  async def handler(
    tool_context: ToolContext,
    arguments: EchoArguments,
  ) -> ToolResult:
    received.append((tool_context, arguments))
    return ToolResult(status="success", data={"value": arguments.value})

  registry = ToolRegistry((_tool("test.echo", handler),))
  result = await registry.execute("test.echo", {"value": 7}, context)

  assert result.status == "success"
  assert result.data == {"value": 7}
  assert received == [(context, EchoArguments(value=7))]
  authorization_check.assert_awaited_once_with(
    context.session,
    context.project_id,
    context.incident_id,
    context.user,
  )


@pytest.mark.asyncio
async def test_execute_returns_explicit_error_for_invalid_arguments(monkeypatch):
  context = _context()
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  handler = AsyncMock(
    return_value=ToolResult(status="success", data={"unexpected": True}),
  )
  registry = ToolRegistry((_tool("test.echo", handler),))

  result = await registry.execute(
    "test.echo",
    {"value": "not-an-integer", "unexpected": True},
    context,
  )

  assert result.status == "error"
  assert result.error == ToolError(
    code="invalid_arguments",
    message="Tool arguments did not match the declared input schema.",
  )
  handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_checks_project_incident_before_dispatch(monkeypatch):
  context = _context()
  authorization_check = AsyncMock(side_effect=PermissionDeniedError())
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    authorization_check,
  )
  handler = AsyncMock(return_value=ToolResult(status="success"))
  registry = ToolRegistry((_tool("test.echo", handler),))

  with pytest.raises(PermissionDeniedError):
    await registry.execute("test.echo", {"value": 7}, context)

  handler.assert_not_awaited()
