import asyncio
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
import httpx
from langgraph.checkpoint.memory import InMemorySaver
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.exceptions import RateLimitExceededError
from app.db import (
  auth,
  environment,
  incident,
  incident_source,
  project_membership,
  user,
)
from app.db.base import Base
from app.db.database import get_db
from app.db.environment import Environment
from app.db.incident import Incident, IncidentEvidence
from app.db.investigation_run import InvestigationRun
from app.db.incident_source import IncidentSource, ProviderAlert, SourceEvent
from app.db.github import (
  GitHubInstallation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.core.config import settings
from app.main import app
from app.services import github_project_service
from app.services import gemini_web_search_service
from app.services.investigation_run_service import fail_stale_investigation_runs
from app.schemas.investigation_schema import IntegrationInvestigationResult
from app.utils.jwt import create_access_token


class FakeRedis:
  def __init__(self):
    self.counts: dict[str, int] = {}

  async def eval(self, _script: str, _key_count: int, key: str, *_args):
    self.counts[key] = self.counts.get(key, 0) + 1
    return self.counts[key]


@pytest_asyncio.fixture
async def incident_client(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'incidents.sqlite3'}",
  )

  @event.listens_for(engine.sync_engine, "connect")
  def enable_sqlite_foreign_keys(connection, _connection_record):
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
    connection.create_function(
      "btrim",
      1,
      lambda value: value.strip(" ") if value is not None else None,
      deterministic=True,
    )

  async with engine.begin() as connection:
    await connection.run_sync(Base.metadata.create_all)

  session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
  )
  fake_redis = FakeRedis()

  async def override_database():
    async with session_factory() as session:
      yield session

  original_overrides = app.dependency_overrides.copy()
  app.dependency_overrides[get_db] = override_database
  app.dependency_overrides[get_redis] = lambda: fake_redis

  transport = ASGITransport(
    app=app,
    client=(f"incident-test-{uuid.uuid4().hex}", 40000),
  )
  async with AsyncClient(transport=transport, base_url="http://testserver") as client:
    yield client, session_factory

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await engine.dispose()


async def _create_user(
  session_factory: async_sessionmaker[AsyncSession],
  label: str,
) -> User:
  async with session_factory() as session:
    created = User(
      email=f"{label}-{secrets.token_hex(8)}@example.com",
      display_name=label,
      password_hash="test-hash",
      email_verified=True,
    )
    session.add(created)
    await session.commit()
    return created


def _headers(user: User) -> dict[str, str]:
  return {"Authorization": f"Bearer {create_access_token(user.id)}"}


async def _create_project(
  client: AsyncClient,
  owner: User,
  name: str,
) -> uuid.UUID:
  response = await client.post(
    "/projects",
    json={"name": name},
    headers=_headers(owner),
  )
  assert response.status_code == 201
  return uuid.UUID(response.json()["id"])


@pytest.mark.asyncio
async def test_project_member_can_report_incident_and_read_its_evidence(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "owner")
  member = await _create_user(session_factory, "member")
  outsider = await _create_user(session_factory, "outsider")
  project_id = await _create_project(client, owner, "Payments")
  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        user_id=member.id,
        role="member",
      ),
    )
    await session.commit()

  body = {
    "incident_type": "service_outage",
    "title": "Checkout is unavailable",
    "description": "Requests to checkout are timing out.",
    "severity": "high",
  }
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json=body,
    headers=_headers(member),
  )
  denied = await client.post(
    f"/projects/{project_id}/incidents",
    json=body,
    headers=_headers(outsider),
  )

  assert created.status_code == 201
  assert denied.status_code == 404
  incident_data = created.json()
  incident_id = incident_data["id"]
  assert incident_data["project_id"] == str(project_id)
  assert incident_data["reported_by_user_id"] == str(member.id)
  assert incident_data["source_type"] == "manual"
  assert incident_data["status"] == "open"
  assert incident_data["severity"] == "high"

  listing = await client.get(
    f"/projects/{project_id}/incidents",
    headers=_headers(owner),
  )
  evidence = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/evidence",
    headers=_headers(member),
  )
  assert listing.status_code == 200
  assert [item["id"] for item in listing.json()] == [incident_id]
  assert evidence.status_code == 200
  assert len(evidence.json()) == 1
  assert evidence.json()[0]["evidence_type"] == "manual_report"
  assert evidence.json()[0]["original_content"]["title"] == body["title"]

  async with session_factory() as session:
    saved = await session.get(Incident, uuid.UUID(incident_id))
    saved_evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.incident_id == uuid.UUID(incident_id),
        ),
      ),
    )
  assert saved is not None
  assert saved.source_event_id is None
  assert len(saved_evidence) == 1


@pytest.mark.asyncio
async def test_authorized_incident_member_can_search_and_persist_grounded_web_evidence(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "web-search-owner")
  project_id = await _create_project(client, owner, "Web Search Project")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={
      "incident_type": "service_outage",
      "title": "Synthetic timeout incident",
      "description": "A test-only public error message.",
      "severity": "high",
    },
    headers=_headers(owner),
  )
  assert created.status_code == 201
  incident_id = created.json()["id"]

  monkeypatch.setattr(settings, "GEMINI_WEB_SEARCH_ENABLED", True)
  monkeypatch.setattr(settings, "GEMINI_API_KEY", SecretStr("synthetic-api-key"))

  async def provider_handler(request: httpx.Request) -> httpx.Response:
    assert request.headers["x-goog-api-key"] == "synthetic-api-key"
    return httpx.Response(
      200,
      json={
        "candidates": [{
          "finishReason": "STOP",
          "content": {
            "parts": [{"text": "A public release note documents the fix."}],
          },
          "groundingMetadata": {
            "groundingChunks": [
              {
                "web": {
                  "uri": "https://example.com/release",
                  "title": "Public release notes",
                },
              },
              {
                "web": {
                  "uri": "javascript:alert(1)",
                  "title": "Invalid source",
                },
              },
            ],
            "webSearchQueries": ["public error timeout release"],
          },
        }],
      },
    )

  monkeypatch.setattr(
    gemini_web_search_service,
    "create_gemini_web_search_client",
    lambda: httpx.AsyncClient(
      transport=httpx.MockTransport(provider_handler),
    ),
  )
  response = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/internet-search",
    json={"query": "public error timeout release"},
    headers=_headers(owner),
  )

  assert response.status_code == 200
  result = response.json()
  assert result["status"] == "success"
  assert result["content_is_untrusted"] is True
  assert result["data"]["sources"] == [{
    "url": "https://example.com/release",
    "title": "Public release notes",
  }]

  repeated = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/internet-search",
    json={"query": "public error timeout release"},
    headers=_headers(owner),
  )
  assert repeated.status_code == 200
  assert repeated.json()["evidence"][0]["id"] == result["evidence"][0]["id"]

  evidence = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/evidence",
    headers=_headers(owner),
  )
  web_evidence = [
    item for item in evidence.json()
    if item["evidence_type"] == "web_search"
  ]
  assert len(web_evidence) == 1
  assert web_evidence[0]["normalized_content"]["content_is_untrusted"] is True
  context = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )
  assert context.status_code == 200
  assert any(
    item["evidence_type"] == "web_search"
    for item in context.json()["evidence"]
  )


@pytest.mark.asyncio
async def test_authorized_member_can_run_bounded_ai_investigation_and_replay(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "ai-investigation-owner")
  project_id = await _create_project(client, owner, "AI Investigation Project")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={
      "incident_type": "service_outage",
      "title": "Synthetic API timeout",
      "description": "Requests intermittently time out in this local test.",
      "severity": "high",
    },
    headers=_headers(owner),
  )
  assert created.status_code == 201
  incident_id = created.json()["id"]
  evidence_response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/evidence",
    headers=_headers(owner),
  )
  assert evidence_response.status_code == 200
  evidence_id = evidence_response.json()[0]["id"]

  monkeypatch.setattr(settings, "AI_INVESTIGATION_ENABLED", True)
  monkeypatch.setattr(settings, "GEMINI_API_KEY", SecretStr("synthetic-api-key"))
  monkeypatch.setattr("app.api.incidents.RUN_TIMEOUT_SECONDS", 0.01)
  monkeypatch.setattr(
    app.state,
    "investigation_checkpointer",
    InMemorySaver(),
    raising=False,
  )
  provider_requests: list[httpx.Request] = []

  async def provider_handler(request: httpx.Request) -> httpx.Response:
    provider_requests.append(request)
    assert request.headers["x-goog-api-key"] == "synthetic-api-key"
    payload = json.loads(request.content)
    if str(request.url).endswith(":countTokens"):
      assert "generateContentRequest" in payload
      return httpx.Response(200, json={"totalTokens": 100})
    await asyncio.sleep(0.05)
    assert payload["generationConfig"]["responseMimeType"] == "application/json"
    assert "tools" not in payload
    decision = {
      "action": "conclude",
      "tool_name": None,
      "arguments": {},
      "claim": "The incident report records intermittent API timeouts.",
      "evidence_ids": [evidence_id],
    }
    return httpx.Response(
      200,
      json={
        "candidates": [{
          "finishReason": "STOP",
          "content": {"parts": [{"text": json.dumps(decision)}]},
        }],
        "usageMetadata": {
          "promptTokenCount": 100,
          "candidatesTokenCount": 25,
          "totalTokenCount": 125,
        },
      },
    )

  monkeypatch.setattr(
    "app.api.incidents.create_gemini_investigation_client",
    lambda: httpx.AsyncClient(transport=httpx.MockTransport(provider_handler)),
  )
  headers = {
    **_headers(owner),
    "Idempotency-Key": "local-ai-investigation-001",
  }
  response = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/investigate-ai",
    json={"question": "What is supported by this incident evidence?"},
    headers=headers,
  )

  assert response.status_code == 200
  run = response.json()
  assert run["status"] == "succeeded", json.dumps(run, sort_keys=True)
  assert run["agent_report"]["outcome"] == "conclusion"
  assert run["agent_report"]["claim"] == (
    "The incident report records intermittent API timeouts."
  )
  assert run["agent_report"]["evidence_citations"] == [evidence_id]
  assert run["agent_report"]["budget_usage"]["model_calls"] == 1
  assert run["agent_report"]["budget_usage"]["model_tokens"] == 125
  assert "max_step_seconds" not in run["request_criteria"]["budget"]
  assert "max_duration_seconds" not in run["request_criteria"]["budget"]
  assert response.headers["X-Investigation-Run-ID"] == run["id"]

  replay = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/investigate-ai",
    json={"question": "What is supported by this incident evidence?"},
    headers=headers,
  )
  assert replay.status_code == 200
  assert replay.json()["id"] == run["id"]
  conflict = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/investigate-ai",
    json={"question": "A different question for the same key."},
    headers=headers,
  )
  assert conflict.status_code == 409
  assert len(provider_requests) == 2
  assert sum(
    str(item.url).endswith(":countTokens")
    for item in provider_requests
  ) == 1
  assert sum(
    str(item.url).endswith(":generateContent")
    for item in provider_requests
  ) == 1

  status_response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs/{run['id']}",
    headers=_headers(owner),
  )
  assert status_response.status_code == 200
  assert status_response.json()["agent_report"] == run["agent_report"]


@pytest.mark.asyncio
async def test_ai_investigation_checks_access_and_configuration(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "ai-investigation-gate-owner")
  outsider = await _create_user(session_factory, "ai-investigation-gate-outsider")
  project_id = await _create_project(client, owner, "AI Investigation Gates")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Gated investigation"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}/investigate-ai"
  )

  disabled = await client.post(
    endpoint,
    json={"question": "What does this evidence support?"},
    headers=_headers(owner),
  )
  assert disabled.status_code == 503

  unauthorized = await client.post(
    endpoint,
    json={"question": "What does this evidence support?"},
    headers=_headers(outsider),
  )
  assert unauthorized.status_code == 404

  monkeypatch.setattr(settings, "AI_INVESTIGATION_ENABLED", True)
  monkeypatch.setattr(settings, "GEMINI_API_KEY", None)
  missing_key = await client.post(
    endpoint,
    json={"question": "What does this evidence support?"},
    headers=_headers(owner),
  )
  assert missing_key.status_code == 503

  monkeypatch.setattr(settings, "GEMINI_API_KEY", SecretStr("synthetic-api-key"))
  monkeypatch.setattr(
    app.state,
    "investigation_checkpointer",
    InMemorySaver(),
    raising=False,
  )
@pytest.mark.asyncio
async def test_on_demand_github_workflow_is_persisted_and_correlated_to_incident(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "github-incident-owner")
  project_id = await _create_project(client, owner, "GitHub incident project")
  incident_response = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "deployment_failure", "title": "Failed deployment"},
    headers=_headers(owner),
  )
  assert incident_response.status_code == 201
  incident_id = uuid.UUID(incident_response.json()["id"])
  run_id = 987654
  commit_sha = "a" * 40
  async with session_factory() as session:
    installation = GitHubInstallation(
      project_id=project_id,
      installation_id=12345,
      account_login="example",
      status="active",
    )
    session.add(installation)
    await session.flush()
    repository = GitHubRepository(
      project_id=project_id,
      installation_id=installation.id,
      github_repo_id=456,
      full_name="example/project",
      owner="example",
      html_url="https://github.com/example/project",
      status="active",
    )
    session.add(repository)
    await session.flush()
    webhook_event = GitHubWebhookEvent(
      project_id=project_id,
      github_repository_id=repository.id,
      delivery_id="failed-workflow-for-incident",
      event_name="workflow_run",
      action="completed",
      payload={
        "repository": {"id": 456},
        "workflow_run": {
          "id": run_id,
          "head_sha": commit_sha,
          "conclusion": "failure",
        },
      },
    )
    session.add(webhook_event)
    session.add(
      IncidentEvidence(
        incident_id=incident_id,
        evidence_type="grafana_notification",
        original_content={
          "alert": {
            "labels": {
              "workflow_run_id": str(run_id),
              "commit_sha": commit_sha,
            },
          },
        },
        normalized_content={
          "status": "firing",
          "labels": {
            "workflow_run_id": str(run_id),
            "commit_sha": commit_sha,
          },
        },
      ),
    )
    await session.commit()
    event_id = webhook_event.id

  async def fake_create_installation_token(installation_id):
    assert installation_id == 12345
    return "installation-token"

  async def fake_get_workflow_run(token, full_name, requested_run_id):
    assert (token, full_name, requested_run_id) == (
      "installation-token",
      "example/project",
      run_id,
    )
    return {
      "id": run_id,
      "head_sha": commit_sha,
      "conclusion": "failure",
      "run_started_at": "2026-11-05T12:00:00Z",
    }

  async def fake_get_workflow_jobs(
    token,
    full_name,
    requested_run_id,
    *,
    page,
    per_page,
  ):
    assert (requested_run_id, page, per_page) == (run_id, 1, 100)
    return [{"name": "tests", "conclusion": "failure"}]

  async def fake_get_commit(token, full_name, sha):
    assert (full_name, sha) == ("example/project", commit_sha)
    return {"sha": sha, "commit": {"message": "Test deployment"}, "files": []}

  async def fake_get_commits(token, full_name, *, page, per_page, ref):
    assert (page, per_page, ref) == (1, 10, commit_sha)
    return [{"sha": commit_sha}]

  async def fake_get_workflow_run_logs(token, full_name, requested_run_id):
    assert requested_run_id == run_id
    return {"available": True, "logs": "test failure", "truncated": False}

  monkeypatch.setattr(
    github_project_service.github_service,
    "create_installation_token",
    fake_create_installation_token,
  )
  monkeypatch.setattr(
    github_project_service.github_service,
    "get_workflow_run",
    fake_get_workflow_run,
  )
  monkeypatch.setattr(
    github_project_service.github_service,
    "get_workflow_jobs",
    fake_get_workflow_jobs,
  )
  monkeypatch.setattr(
    github_project_service.github_service,
    "get_commit",
    fake_get_commit,
  )
  monkeypatch.setattr(
    github_project_service.github_service,
    "get_commits",
    fake_get_commits,
  )
  monkeypatch.setattr(
    github_project_service.github_service,
    "get_workflow_run_logs",
    fake_get_workflow_run_logs,
  )

  investigation = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/investigate",
    headers=_headers(owner),
    json={
      "github": {
        "repository_id": 456,
        "event_id": str(event_id),
      },
    },
  )

  assert investigation.status_code == 200
  body = investigation.json()
  assert body["integrations"]["github"]["status"] == "success"
  github_evidence_id = body["integrations"]["github"]["evidence_id"]
  github_evidence = next(
    item for item in body["evidence"]
    if item["id"] == github_evidence_id
  )
  assert github_evidence["evidence_type"] == "github_context"
  assert github_evidence["normalized_content"]["workflow_run"]["id"] == run_id

  context = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )
  assert context.status_code == 200
  context_body = context.json()
  correlation_pairs = {
    (
      item["kind"],
      item["value"],
      item["left_evidence_id"],
      item["right_evidence_id"],
    )
    for item in context_body["correlations"]
  }
  assert any(
    kind == "shared_workflow_run"
    and value == str(run_id)
    and github_evidence_id in {left_id, right_id}
    for kind, value, left_id, right_id in correlation_pairs
  )


@pytest.mark.asyncio
async def test_webhook_event_creates_one_incident_and_preserves_evidence(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "Payments")
  created_source = await client.post(
    f"/projects/{project_id}/sources",
    json={"name": "Alertmanager"},
    headers=_headers(owner),
  )
  source = created_source.json()
  body = {
    "event_id": "prom-alert-100",
    "event_type": "infrastructure",
    "title": "High memory use",
    "description": "Memory use exceeded threshold",
    "severity": "critical",
    "labels": {"service": "payments"},
  }
  webhook_headers = {"Authorization": f"Bearer {source['credential']}"}
  url = f"/webhooks/sources/{source['id']}"

  first = await client.post(url, json=body, headers=webhook_headers)
  duplicate = await client.post(url, json=body, headers=webhook_headers)

  assert first.status_code == 201
  assert duplicate.status_code == 200
  assert first.json()["incident_id"] == duplicate.json()["incident_id"]
  assert first.json()["duplicate"] is False
  assert duplicate.json()["duplicate"] is True

  incident_id = first.json()["incident_id"]
  listing = await client.get(
    f"/projects/{project_id}/incidents",
    headers=_headers(owner),
  )
  evidence = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/evidence",
    headers=_headers(owner),
  )
  assert listing.status_code == 200
  assert len(listing.json()) == 1
  assert listing.json()[0]["source_type"] == "generic_webhook"
  assert listing.json()[0]["source_event_id"] == first.json()["event"]["id"]
  assert evidence.status_code == 200
  assert len(evidence.json()) == 1
  assert evidence.json()[0]["original_content"] == body

  async with session_factory() as session:
    incidents = list(
      await session.scalars(
        select(Incident).where(Incident.project_id == project_id),
      ),
    )
    evidence_rows = list(await session.scalars(select(IncidentEvidence)))
  assert len(incidents) == 1
  assert len(evidence_rows) == 1


@pytest.mark.asyncio
async def test_incident_status_transitions_and_project_isolation(incident_client):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "owner")
  outsider = await _create_user(session_factory, "outsider")
  project_id = await _create_project(client, owner, "Private")
  other_project_id = await _create_project(client, outsider, "Other")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "manual", "title": "Host unavailable"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]

  acknowledged = await client.patch(
    f"/projects/{project_id}/incidents/{incident_id}/status",
    json={"status": "acknowledged"},
    headers=_headers(owner),
  )
  resolved = await client.patch(
    f"/projects/{project_id}/incidents/{incident_id}/status",
    json={"status": "resolved"},
    headers=_headers(owner),
  )
  reopened = await client.patch(
    f"/projects/{project_id}/incidents/{incident_id}/status",
    json={"status": "open"},
    headers=_headers(owner),
  )
  resolved_again = await client.patch(
    f"/projects/{project_id}/incidents/{incident_id}/status",
    json={"status": "resolved"},
    headers=_headers(owner),
  )
  invalid = await client.patch(
    f"/projects/{project_id}/incidents/{incident_id}/status",
    json={"status": "acknowledged"},
    headers=_headers(owner),
  )
  cross_project = await client.get(
    f"/projects/{other_project_id}/incidents/{incident_id}",
    headers=_headers(outsider),
  )

  assert acknowledged.status_code == 200
  assert acknowledged.json()["status"] == "acknowledged"
  assert resolved.status_code == 200
  assert resolved.json()["resolved_at"] is not None
  assert reopened.status_code == 200
  assert reopened.json()["status"] == "open"
  assert reopened.json()["resolved_at"] is None
  assert resolved_again.status_code == 200
  assert invalid.status_code == 409
  assert cross_project.status_code == 404


@pytest.mark.asyncio
async def test_manual_incident_rejects_environment_from_another_project(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "One")
  other_project_id = await _create_project(client, owner, "Two")
  async with session_factory() as session:
    environment = Environment(
      project_id=other_project_id,
      name="Production",
      environment_type="production",
    )
    session.add(environment)
    await session.commit()
    environment_id = environment.id

  response = await client.post(
    f"/projects/{project_id}/incidents",
    json={
      "incident_type": "service_outage",
      "title": "Wrong environment",
      "environment_id": str(environment_id),
    },
    headers=_headers(owner),
  )
  assert response.status_code == 404


@pytest.mark.asyncio
async def test_incident_context_is_bounded_project_scoped_and_correlates_evidence(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "context-owner")
  outsider = await _create_user(session_factory, "context-outsider")
  project_id = await _create_project(client, owner, "Context project")
  other_project_id = await _create_project(client, owner, "Other context project")

  first_incident_response = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Checkout unavailable"},
    headers=_headers(owner),
  )
  second_incident_response = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Different incident"},
    headers=_headers(owner),
  )
  other_incident_response = await client.post(
    f"/projects/{other_project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Other project incident"},
    headers=_headers(owner),
  )
  assert first_incident_response.status_code == 201
  assert second_incident_response.status_code == 201
  assert other_incident_response.status_code == 201
  incident_id = uuid.UUID(first_incident_response.json()["id"])
  second_incident_id = uuid.UUID(second_incident_response.json()["id"])
  other_incident_id = uuid.UUID(other_incident_response.json()["id"])

  trace_id = "0123456789abcdef0123456789abcdef"
  source_id = uuid.uuid4()
  evidence_ids = {uuid.uuid4() for _ in range(3)}
  timestamp = datetime(2025, 1, 1, tzinfo=UTC)
  async with session_factory() as session:
    session.add(
      IncidentSource(
        id=source_id,
        project_id=project_id,
        name="Context Prometheus",
        source_type="prometheus",
        prometheus_url="http://prometheus.example",
        prometheus_auth_type="bearer",
        prometheus_auth_ciphertext="must-not-appear-in-context",
        credential_hash="a" * 64,
      ),
    )
    await session.flush()
    session.add_all(
      [
        IncidentEvidence(
          id=evidence_ids.pop(),
          incident_id=incident_id,
          evidence_type="trace_spans",
          original_content={
            "query": {},
            "traces": [
              {
                "trace_id": trace_id,
                "spans": [
                  {
                    "trace_id": trace_id,
                    "service_name": "checkout",
                    "start_time_unix_nano": "1700000001123456789",
                  },
                ],
              },
            ],
          },
          normalized_content={
            "status": "success",
            "retrieved_at": "2023-11-14T22:15:00Z",
          },
          created_at=timestamp,
        ),
        IncidentEvidence(
          id=evidence_ids.pop(),
          incident_id=incident_id,
          evidence_type="loki_logs",
          original_content={
            "entries": [
              {
                "timestamp": "1700000000123456789",
                "line": "untrusted log content",
                "labels": {
                  "trace_id": trace_id,
                  "service_name": "checkout",
                },
              },
            ],
          },
          normalized_content={
            "status": "success",
            "time_range": {
              "start": "2023-11-14T22:13:00Z",
              "end": "2023-11-14T22:14:00Z",
            },
            "retrieved_at": "2023-11-14T22:15:00Z",
          },
          created_at=timestamp,
        ),
        IncidentEvidence(
          id=evidence_ids.pop(),
          incident_id=incident_id,
          incident_source_id=source_id,
          query_hash="metric-query-hash",
          evidence_type="prometheus_metrics",
          original_content={
            "expression": "up",
            "results": [
              {
                "metric": {"service": "checkout"},
                "values": [[1700000002.5, "1"]],
              },
            ],
          },
          normalized_content={
            "status": "partial",
            "result_type": "matrix",
            "partial": True,
            "retrieved_at": "2023-11-14T22:16:00Z",
          },
          created_at=timestamp,
        ),
      ],
    )
    await session.commit()

  response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )
  repeated_response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )
  assert response.status_code == 200
  assert repeated_response.status_code == 200
  context = response.json()
  assert [item["id"] for item in context["timeline"]] == [
    item["id"] for item in repeated_response.json()["timeline"]
  ]
  assert context["correlations"] == repeated_response.json()["correlations"]
  evidence_types = {
    item["id"]: item["evidence_type"] for item in context["evidence"]
  }
  assert set(evidence_types.values()) == {
    "manual_report",
    "trace_spans",
    "loki_logs",
    "prometheus_metrics",
  }
  assert context["total_evidence_count"] == 4
  assert context["evidence_truncated"] is False
  assert context["content_is_untrusted"] is True
  assert all(item["content_is_untrusted"] for item in context["evidence"])
  assert all("original_content" not in item for item in context["evidence"])
  assert "must-not-appear-in-context" not in response.text
  assert any("execution history is not persisted" in gap for gap in context["gaps"])
  prometheus_evidence = next(
    item for item in context["evidence"]
    if item["evidence_type"] == "prometheus_metrics"
  )
  loki_evidence = next(
    item for item in context["evidence"]
    if item["evidence_type"] == "loki_logs"
  )
  assert prometheus_evidence["partial"] is True
  assert prometheus_evidence["retrieved_at"] == "2023-11-14T22:16:00Z"
  assert prometheus_evidence["query_time_range"] is None
  assert loki_evidence["query_time_range"] == {
    "start": "2023-11-14T22:13:00Z",
    "end": "2023-11-14T22:14:00Z",
  }

  timeline = context["timeline"]
  assert [item["occurred_at"] for item in timeline if item["event_type"] == "log_entry"]
  assert any(item["event_type"] == "trace_span_started" for item in timeline)
  sample = next(
    item for item in timeline
    if item["event_type"] == "prometheus_series_observation"
  )
  assert sample["timestamp_kind"] == "series_last_sample_time"
  assert sample["occurred_at"] == "2023-11-14T22:13:22.500000Z"
  assert sample["details"]["sample_count"] == 1

  correlations = context["correlations"]
  trace_correlation = next(
    relation for relation in correlations
    if relation["kind"] == "shared_trace_id"
    and relation["value"] == trace_id
  )
  assert trace_correlation["left_time_range"] is not None
  assert trace_correlation["right_time_range"] is not None
  assert trace_correlation["left_time_range"]["start"].endswith("Z")
  assert trace_correlation["right_time_range"]["end"].endswith("Z")
  assert any(
    relation["kind"] == "shared_service"
    and relation["value"] == "checkout"
    for relation in correlations
  )
  assert all("cause" not in relation["explanation"].lower() for relation in correlations)

  prometheus_coverage = next(
    item for item in context["source_coverage"]
    if item["source_type"] == "prometheus"
  )
  assert prometheus_coverage == {
    "source_type": "prometheus",
    "configured_count": 1,
    "enabled_count": 1,
    "evidence_count": 1,
  }

  cross_incident = await client.get(
    f"/projects/{project_id}/incidents/{second_incident_id}/context",
    headers=_headers(owner),
  )
  cross_project = await client.get(
    f"/projects/{project_id}/incidents/{other_incident_id}/context",
    headers=_headers(owner),
  )
  outsider_response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(outsider),
  )
  assert cross_incident.status_code == 200
  assert cross_incident.json()["total_evidence_count"] == 1
  assert cross_project.status_code == 404
  assert outsider_response.status_code == 404


@pytest.mark.asyncio
async def test_context_counts_alert_evidence_for_its_configured_source(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "alert-context-owner")
  project_id = await _create_project(client, owner, "Alert coverage")
  incident_response = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Alert evidence"},
    headers=_headers(owner),
  )
  assert incident_response.status_code == 201
  incident_id = uuid.UUID(incident_response.json()["id"])
  source_id = uuid.uuid4()
  alert_id = uuid.uuid4()
  async with session_factory() as session:
    source = IncidentSource(
      id=source_id,
      project_id=project_id,
      name="Context Grafana source",
      source_type="grafana",
      credential_hash="b" * 64,
    )
    session.add(source)
    await session.flush()
    webhook_source = IncidentSource(
      id=uuid.uuid4(),
      project_id=project_id,
      name="Context webhook source",
      source_type="generic_webhook",
      credential_hash="c" * 64,
    )
    session.add(webhook_source)
    await session.flush()
    source_event = SourceEvent(
      id=uuid.uuid4(),
      source_id=webhook_source.id,
      project_id=project_id,
      environment_id=None,
      external_event_id="coverage-event",
      event_type="deployment",
      title="Deployment event",
      description=None,
      severity="medium",
      original_payload={"labels": {"service_name": "checkout"}},
    )
    session.add(source_event)
    await session.flush()
    session.add(
      ProviderAlert(
        id=alert_id,
        source_id=source_id,
        project_id=project_id,
        incident_id=incident_id,
        fingerprint="context-alert-fingerprint",
        status="firing",
        alert_name="CheckoutDown",
        severity="critical",
        summary="Checkout is unavailable",
        description=None,
        labels={"service_name": "checkout"},
        annotations={},
        starts_at=datetime(2025, 1, 1, tzinfo=UTC),
        ends_at=None,
        generator_url=None,
        latest_payload={},
        first_received_at=datetime(2025, 1, 1, tzinfo=UTC),
        last_received_at=datetime(2025, 1, 1, tzinfo=UTC),
        resolved_at=None,
      ),
    )
    await session.flush()
    session.add_all(
      [
        IncidentEvidence(
          incident_id=incident_id,
          alertmanager_alert_id=alert_id,
          evidence_type="grafana_notification",
          original_content={"alert": {"labels": {"service_name": "checkout"}}},
          normalized_content={
            "status": "firing",
            "labels": {"service_name": "checkout"},
          },
        ),
        IncidentEvidence(
          incident_id=incident_id,
          source_event_id=source_event.id,
          evidence_type="webhook_payload",
          original_content={"labels": {"service_name": "checkout"}},
          normalized_content={"status": "success"},
        ),
      ],
    )
    await session.commit()

  response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )

  assert response.status_code == 200
  coverage = next(
    item for item in response.json()["source_coverage"]
    if item["source_type"] == "grafana"
  )
  assert coverage == {
    "source_type": "grafana",
    "configured_count": 1,
    "enabled_count": 1,
    "evidence_count": 1,
  }
  webhook_coverage = next(
    item for item in response.json()["source_coverage"]
    if item["source_type"] == "generic_webhook"
  )
  assert webhook_coverage == {
    "source_type": "generic_webhook",
    "configured_count": 1,
    "enabled_count": 1,
    "evidence_count": 1,
  }


@pytest.mark.asyncio
async def test_incident_context_caps_returned_evidence(incident_client):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "bounded-context-owner")
  project_id = await _create_project(client, owner, "Bounded context")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Many evidence records"},
    headers=_headers(owner),
  )
  assert created.status_code == 201
  incident_id = uuid.UUID(created.json()["id"])

  async with session_factory() as session:
    session.add_all(
      [
        IncidentEvidence(
          id=uuid.uuid4(),
          incident_id=incident_id,
          evidence_type="manual_report",
          original_content={"report": f"report-{index}"},
          normalized_content={},
        )
        for index in range(105)
      ],
    )
    await session.commit()

  response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/context",
    headers=_headers(owner),
  )

  assert response.status_code == 200
  context = response.json()
  assert len(context["evidence"]) == context["evidence_limit"] == 100
  assert context["total_evidence_count"] == 106
  assert context["evidence_truncated"] is True
  assert any("limited to the first 100" in gap for gap in context["gaps"])


@pytest.mark.asyncio
async def test_investigation_runs_are_persisted_idempotent_and_project_scoped(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "durable-run-owner")
  outsider = await _create_user(session_factory, "durable-run-outsider")
  project_id = await _create_project(client, owner, "Durable runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Run lifecycle"},
    headers=_headers(owner),
  )
  assert created.status_code == 201
  incident_id = created.json()["id"]
  calls = 0

  async def fake_investigation(
    _session,
    _redis,
    _project_id,
    _incident_id,
    _user,
    request,
  ):
    nonlocal calls
    calls += 1
    aggregate_status = (
      "partial"
      if request.docker.log_tail_lines == 30
      else "success"
    )
    return aggregate_status, {
      "docker": IntegrationInvestigationResult(
        status="partial" if aggregate_status == "partial" else "success",
      ),
    }

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    fake_investigation,
  )
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}/investigate"
  )
  request_body = {
    "docker": {
      "source_id": str(uuid.uuid4()),
      "container_id": "a" * 64,
      "log_tail_lines": 20,
    },
  }
  headers = {**_headers(owner), "Idempotency-Key": "durable-test-run-1"}
  first = await client.post(endpoint, headers=headers, json=request_body)
  replay = await client.post(endpoint, headers=headers, json=request_body)

  assert first.status_code == replay.status_code == 200
  assert first.json() == replay.json()
  assert first.headers["X-Investigation-Run-ID"] == replay.headers["X-Investigation-Run-ID"]
  assert calls == 1

  history = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(owner),
  )
  assert history.status_code == 200
  assert len(history.json()) == 1
  run = history.json()[0]
  assert run["status"] == "succeeded"
  assert run["aggregate_status"] == "success"
  assert run["requested_integrations"] == ["docker"]
  assert run["attempt_count"] == 1
  assert run["completed_at"] is not None

  detail = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs/{run['id']}",
    headers=_headers(owner),
  )
  denied = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(outsider),
  )
  conflict = await client.post(
    endpoint,
    headers=headers,
    json={
      "docker": {
        **request_body["docker"],
        "log_tail_lines": 21,
      },
    },
  )
  assert detail.status_code == 200
  assert detail.json() == run
  assert denied.status_code == 404
  assert conflict.status_code == 409
  assert calls == 1
  retried = await client.post(
    endpoint,
    headers={**_headers(owner), "Idempotency-Key": "durable-test-run-2"},
    json={
      "docker": {
        **request_body["docker"],
        "log_tail_lines": 30,
      },
    },
  )
  assert retried.status_code == 200
  assert retried.json()["status"] == "partial"
  assert calls == 2
  retried_history = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(owner),
  )
  statuses_by_run_id = {
    item["id"]: item["status"]
    for item in retried_history.json()
  }
  assert statuses_by_run_id[first.headers["X-Investigation-Run-ID"]] == "succeeded"
  assert statuses_by_run_id[retried.headers["X-Investigation-Run-ID"]] == "partial"


@pytest.mark.asyncio
async def test_unexpected_investigation_failure_is_recorded(
  incident_client,
  monkeypatch,
):
  client, _session_factory = incident_client
  owner = await _create_user(_session_factory, "durable-run-failure-owner")
  project_id = await _create_project(client, owner, "Failed runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Unexpected failure"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]

  async def fail_investigation(*_args):
    raise RuntimeError("internal detail must not be persisted")

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    fail_investigation,
  )
  headers = {
    **_headers(owner),
    "Idempotency-Key": "durable-test-run-failure",
  }
  with pytest.raises(RuntimeError, match="internal detail"):
    await client.post(
      f"/projects/{project_id}/incidents/{incident_id}/investigate",
      headers=headers,
      json={
        "docker": {
          "source_id": str(uuid.uuid4()),
          "container_id": "b" * 64,
        },
      },
    )

  history = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(owner),
  )
  assert history.status_code == 200
  run = history.json()[0]
  assert run["status"] == "failed"
  assert run["failure_code"] == "RuntimeError"
  assert "internal detail" not in run["failure_detail"]


@pytest.mark.asyncio
async def test_concurrent_duplicate_run_is_not_executed_twice(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "durable-run-concurrent-owner")
  project_id = await _create_project(client, owner, "Concurrent durable runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Concurrent run"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]
  started = asyncio.Event()
  release = asyncio.Event()
  calls = 0

  async def slow_investigation(*_args):
    nonlocal calls
    calls += 1
    started.set()
    await release.wait()
    return "success", {
      "docker": IntegrationInvestigationResult(status="success"),
    }

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    slow_investigation,
  )
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}/investigate"
  )
  headers = {
    **_headers(owner),
    "Idempotency-Key": "durable-concurrent-run",
  }
  request_body = {
    "docker": {
      "source_id": str(uuid.uuid4()),
      "container_id": "c" * 64,
    },
  }
  first_task = asyncio.create_task(
    client.post(endpoint, headers=headers, json=request_body),
  )
  await asyncio.wait_for(started.wait(), timeout=5)
  duplicate = await client.post(endpoint, headers=headers, json=request_body)
  release.set()
  first = await first_task

  assert duplicate.status_code == 409
  assert duplicate.json()["detail"]["run_id"] == first.headers["X-Investigation-Run-ID"]
  assert first.status_code == 200
  assert calls == 1


@pytest.mark.asyncio
async def test_cancelled_run_is_marked_cancelled(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "durable-run-cancel-owner")
  project_id = await _create_project(client, owner, "Cancelled durable runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Cancelled run"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]
  started = asyncio.Event()

  async def cancellable_investigation(*_args):
    started.set()
    await asyncio.Event().wait()

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    cancellable_investigation,
  )
  task = asyncio.create_task(
    client.post(
      f"/projects/{project_id}/incidents/{incident_id}/investigate",
      headers={
        **_headers(owner),
        "Idempotency-Key": "durable-cancelled-run",
      },
      json={
        "docker": {
          "source_id": str(uuid.uuid4()),
          "container_id": "d" * 64,
        },
      },
    ),
  )
  await asyncio.wait_for(started.wait(), timeout=5)
  task.cancel()
  with pytest.raises(asyncio.CancelledError):
    await task

  history = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(owner),
  )
  assert history.status_code == 200
  assert history.json()[0]["status"] == "cancelled"


@pytest.mark.asyncio
async def test_timed_out_investigation_is_recorded_as_failed(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "durable-run-timeout-owner")
  project_id = await _create_project(client, owner, "Timed-out durable runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Timed out run"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]
  monkeypatch.setattr("app.api.incidents.RUN_TIMEOUT_SECONDS", 0.01)

  async def slow_investigation(*_args):
    await asyncio.sleep(1)

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    slow_investigation,
  )
  with pytest.raises(TimeoutError):
    await client.post(
      f"/projects/{project_id}/incidents/{incident_id}/investigate",
      headers={
        **_headers(owner),
        "Idempotency-Key": "durable-timeout-run",
      },
      json={
        "docker": {
          "source_id": str(uuid.uuid4()),
          "container_id": "e" * 64,
        },
      },
    )

  history = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs",
    headers=_headers(owner),
  )
  assert history.status_code == 200
  run = history.json()[0]
  assert run["status"] == "failed"
  assert run["failure_code"] == "TimeoutError"


@pytest.mark.asyncio
async def test_stale_running_run_is_marked_interrupted(
  incident_client,
  monkeypatch,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "durable-run-stale-owner")
  project_id = await _create_project(client, owner, "Stale durable runs")
  created = await client.post(
    f"/projects/{project_id}/incidents",
    json={"incident_type": "service_outage", "title": "Stale run"},
    headers=_headers(owner),
  )
  incident_id = created.json()["id"]

  async def successful_investigation(*_args):
    return "success", {
      "docker": IntegrationInvestigationResult(status="success"),
    }

  monkeypatch.setattr(
    "app.api.incidents.investigate_incident_integrations",
    successful_investigation,
  )
  result = await client.post(
    f"/projects/{project_id}/incidents/{incident_id}/investigate",
    headers={
      **_headers(owner),
      "Idempotency-Key": "durable-stale-run",
    },
    json={
      "docker": {
        "source_id": str(uuid.uuid4()),
        "container_id": "f" * 64,
      },
    },
  )
  assert result.status_code == 200
  run_id = result.headers["X-Investigation-Run-ID"]
  async with session_factory() as session:
    run = await session.get(InvestigationRun, uuid.UUID(run_id))
    assert run is not None
    run.status = "running"
    run.completed_at = None
    run.started_at = datetime.now(UTC) - timedelta(minutes=10)
    await session.commit()

  response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}/investigation-runs/{run_id}",
    headers=_headers(owner),
  )
  assert response.status_code == 200
  assert response.json()["status"] == "failed"
  assert response.json()["failure_code"] == "execution_interrupted"


@pytest.mark.asyncio
async def test_running_agent_run_is_not_failed_by_stale_cleanup(
  incident_client,
):
  client, session_factory = incident_client
  owner = await _create_user(session_factory, "agent-run-owner")
  project_id = await _create_project(client, owner, "Agent run recovery")
  created_incident = await client.post(
    f"/projects/{project_id}/incidents",
    json={
      "incident_type": "service_outage",
      "title": "Recovery test incident",
      "description": "Synthetic recovery scenario.",
    },
    headers=_headers(owner),
  )
  assert created_incident.status_code == 201
  incident_id = uuid.UUID(created_incident.json()["id"])
  run = InvestigationRun(
    project_id=project_id,
    incident_id=incident_id,
    requested_by_user_id=owner.id,
    request_hash="b" * 64,
    requested_integrations=["investigation_graph"],
    request_criteria={"mode": "bounded_ai_investigation"},
    status="running",
    started_at=datetime.now(UTC) - timedelta(hours=1),
  )
  async with session_factory() as session:
    session.add(run)
    await session.commit()
    run_id = run.id
    await fail_stale_investigation_runs(session, incident_id)
    refreshed = await session.get(InvestigationRun, run_id)
    if refreshed is not None:
      await session.refresh(refreshed)

  assert refreshed is not None
  assert refreshed.status == "running"
  assert refreshed.failure_code is None
