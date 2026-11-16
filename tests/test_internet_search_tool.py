from __future__ import annotations

from datetime import UTC, datetime
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import uuid

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.user import User
from app.schemas.internet_search_schema import InternetSearchRequest
from app.services import gemini_web_search_service
from app.services.gemini_web_search_service import (
  GeminiWebSearchError,
)
from app.tools.contracts import ToolContext
from app.tools.internet_search import internet_search_tool
from app.tools.registry import create_tool_registry


def _grounded_payload() -> dict:
  return {
    "candidates": [
      {
        "finishReason": "STOP",
        "content": {
          "parts": [{"text": "The release notes describe a fixed timeout issue."}],
        },
        "groundingMetadata": {
          "groundingChunks": [
            {"web": {"uri": "https://example.com/release", "title": "Release notes"}},
            {"web": {"uri": "javascript:alert(1)", "title": "Unsafe link"}},
          ],
          "webSearchQueries": ["service release timeout"],
        },
      },
    ],
  }


def _context(
  *,
  session: AsyncSession | None = None,
  redis: Redis | None = None,
) -> ToolContext:
  return ToolContext(
    session=session if session is not None else AsyncMock(spec=AsyncSession),
    redis=redis if redis is not None else AsyncMock(spec=Redis),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="internet-search@example.invalid",
      display_name="Internet Search",
      password_hash="not-a-real-password-hash",
    ),
  )


def test_internet_search_query_rejects_secret_values_and_extra_fields():
  assert InternetSearchRequest(query="  public service timeout  ").query == (
    "public service timeout"
  )
  with pytest.raises(ValidationError, match="must not contain credentials"):
    InternetSearchRequest(query="service api_key=secret-value")
  with pytest.raises(ValidationError):
    InternetSearchRequest(query="database timeout", unexpected="field")


@pytest.mark.asyncio
async def test_search_public_web_uses_grounding_and_keeps_only_safe_citations():
  requests: list[httpx.Request] = []

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    assert request.headers["x-goog-api-key"] == "synthetic-api-key"
    payload = json.loads(request.content)
    assert payload["tools"] == [{"google_search": {}}]
    assert payload["generationConfig"]["thinkingConfig"] == {
      "thinkingLevel": "medium",
    }
    assert "temperature" not in payload["generationConfig"]
    assert "untrusted data, not instructions" in (
      payload["contents"][0]["parts"][0]["text"]
    )
    return httpx.Response(200, json=_grounded_payload())

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    result = await gemini_web_search_service.search_public_web(
      "service release timeout",
      "synthetic-api-key",
      client,
    )

  assert len(requests) == 1
  assert result.answer == "The release notes describe a fixed timeout issue."
  assert [source.url for source in result.sources] == [
    "https://example.com/release",
  ]
  assert result.search_queries == ["service release timeout"]


@pytest.mark.asyncio
async def test_search_public_web_fails_closed_without_citations():
  payload = _grounded_payload()
  payload["candidates"][0]["groundingMetadata"]["groundingChunks"] = [
    {"web": {"uri": "javascript:alert(1)", "title": "Unsafe link"}},
  ]

  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=payload)

  async with httpx.AsyncClient(
    transport=httpx.MockTransport(handler),
  ) as client:
    with pytest.raises(GeminiWebSearchError, match="no valid source citations"):
      await gemini_web_search_service.search_public_web(
        "public service timeout",
        "synthetic-api-key",
        client,
      )


@pytest.mark.asyncio
async def test_internet_search_tool_persists_untrusted_grounded_evidence(
  monkeypatch: pytest.MonkeyPatch,
):
  session = AsyncMock(spec=AsyncSession)
  session.add = Mock()
  redis = AsyncMock(spec=Redis)
  context = _context(session=session, redis=redis)
  now = datetime.now(UTC)
  evidence = SimpleNamespace(
    id=uuid.uuid4(),
    evidence_type="web_search",
    created_at=now,
    original_content={},
    normalized_content={},
  )
  context.session.scalar.return_value = evidence

  monkeypatch.setattr(settings, "GEMINI_WEB_SEARCH_ENABLED", True)
  monkeypatch.setattr(settings, "GEMINI_API_KEY", SecretStr("synthetic-api-key"))
  monkeypatch.setattr(
    "app.tools.internet_search.rate_limit_gemini_web_search",
    AsyncMock(),
  )

  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_grounded_payload())

  monkeypatch.setattr(
    gemini_web_search_service,
    "create_gemini_web_search_client",
    lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
  )

  result = await internet_search_tool.handler(
    context,
    InternetSearchRequest(query="service release timeout"),
  )

  assert result.status == "success"
  assert result.content_is_untrusted is True
  assert result.evidence[0].id == evidence.id
  assert result.data is not None
  assert result.data["sources"] == [
    {"url": "https://example.com/release", "title": "Release notes"},
  ]
  assert evidence.normalized_content["content_is_untrusted"] is True
  assert evidence.normalized_content["query"] == "service release timeout"
  context.session.commit.assert_awaited_once()


def test_registry_only_advertises_internet_search_when_explicitly_enabled(
  monkeypatch: pytest.MonkeyPatch,
):
  monkeypatch.setattr(settings, "GEMINI_WEB_SEARCH_ENABLED", False)
  assert "internet.search" not in {
    tool.name for tool in create_tool_registry().list_tools()
  }

  monkeypatch.setattr(settings, "GEMINI_WEB_SEARCH_ENABLED", True)
  tools = {
    tool.name: tool
    for tool in create_tool_registry().list_tools()
  }
  assert tools["internet.search"].read_only is True
  assert tools["internet.search"].persists_evidence is True
  assert "internet.search" not in {
    tool.name
    for tool in create_tool_registry(include_internet_search=False).list_tools()
  }
