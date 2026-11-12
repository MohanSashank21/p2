from __future__ import annotations

import json
import os
import uuid

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault(
  "JWT_ACCESS_SECRET_KEY",
  "test-access-secret-not-for-production-000001",
)
os.environ.setdefault(
  "JWT_REFRESH_SECRET_KEY",
  "test-refresh-secret-not-for-production-000002",
)
os.environ.setdefault(
  "OTP_HASH_SECRET_KEY",
  "test-otp-hmac-secret-not-for-production-000003",
)

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.db import (
  auth,
  environment,
  incident,
  incident_source,
  investigation_run,
  project,
  project_membership,
  user,
)
from app.db.base import Base
from app.db.database import get_db
from app.db.incident import IncidentEvidence
from app.db.investigation_run import InvestigationRun
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.utils.jwt import create_access_token


class FakeRedis:
  def __init__(self) -> None:
    self.counts: dict[str, int] = {}

  async def eval(self, _script: str, _key_count: int, key: str, *_args):
    self.counts[key] = self.counts.get(key, 0) + 1
    return self.counts[key]


@pytest_asyncio.fixture
async def synthesis_client(tmp_path, monkeypatch):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'synthesis.sqlite3'}",
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
  monkeypatch.setattr(settings, "GEMINI_SYNTHESIS_ENABLED", True)
  monkeypatch.setattr(
    settings,
    "GEMINI_API_KEY",
    SecretStr("test-gemini-key"),
  )

  transport = ASGITransport(
    app=app,
    client=(f"synthesis-test-{uuid.uuid4().hex}", 40000),
  )
  async with AsyncClient(
    transport=transport,
    base_url="http://testserver",
  ) as client:
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
      email=f"{label}-{uuid.uuid4().hex}@example.com",
      display_name=label,
      password_hash="test-hash",
      email_verified=True,
    )
    session.add(created)
    await session.commit()
    return created


def _headers(user: User) -> dict[str, str]:
  return {"Authorization": f"Bearer {create_access_token(user.id)}"}


async def _create_run(
  session_factory: async_sessionmaker[AsyncSession],
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
) -> tuple[uuid.UUID, uuid.UUID]:
  async with session_factory() as session:
    evidence = IncidentEvidence(
      incident_id=incident_id,
      evidence_type="manual_report",
      original_content={
        "private_raw_payload": "must-not-be-sent-to-gemini",
      },
      normalized_content={
        "description": "checkout latency increased",
        "log": "Authorization: Bearer ghp_123456789012345678901234567890",
        "password": "also-must-not-be-sent",
      },
    )
    session.add(evidence)
    await session.flush()
    run = InvestigationRun(
      project_id=project_id,
      incident_id=incident_id,
      requested_by_user_id=None,
      request_hash="a" * 64,
      requested_integrations=["manual_report"],
      request_criteria={},
      status="succeeded",
      aggregate_status="success",
      integration_results={},
      evidence_ids=[str(evidence.id)],
    )
    session.add(run)
    await session.commit()
    return run.id, evidence.id


async def _create_incident(
  client: AsyncClient,
  owner: User,
) -> tuple[uuid.UUID, uuid.UUID]:
  project_response = await client.post(
    "/projects",
    json={"name": f"Synthesis-{uuid.uuid4().hex[:8]}"},
    headers=_headers(owner),
  )
  assert project_response.status_code == 201
  project_id = uuid.UUID(project_response.json()["id"])
  incident_response = await client.post(
    f"/projects/{project_id}/incidents",
    json={
      "incident_type": "service_outage",
      "title": "Checkout latency regression",
      "description": "Checkout requests became slow.",
    },
    headers=_headers(owner),
  )
  assert incident_response.status_code == 201
  return project_id, uuid.UUID(incident_response.json()["id"])


def _candidate(evidence_id: uuid.UUID) -> dict:
  report = {
    "status": "conclusion",
    "findings": [
      {
        "kind": "conclusion",
        "claim": "Checkout latency increased in the supplied report.",
        "evidence_ids": [str(evidence_id)],
        "confidence": "moderate",
      },
    ],
    "data_gaps": [],
    "next_steps": [],
  }
  return {
    "candidates": [
      {
        "finishReason": "STOP",
        "content": {"parts": [{"text": json.dumps(report)}]},
      },
    ],
    "usageMetadata": {
      "promptTokenCount": 150,
      "candidatesTokenCount": 35,
    },
  }


@pytest.mark.asyncio
async def test_synthesis_is_user_triggered_scoped_and_persisted(
  synthesis_client,
  monkeypatch,
):
  client, session_factory = synthesis_client
  owner = await _create_user(session_factory, "synthesis-owner")
  project_id, incident_id = await _create_incident(client, owner)
  run_id, evidence_id = await _create_run(
    session_factory,
    project_id,
    incident_id,
  )
  requests = []

  async def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    body = json.loads(request.content)
    prompt = body["contents"][0]["parts"][0]["text"]
    assert str(evidence_id) in prompt
    assert "must-not-be-sent-to-gemini" not in prompt
    assert "also-must-not-be-sent" not in prompt
    assert "ghp_123456789012345678901234567890" not in prompt
    return httpx.Response(200, json=_candidate(evidence_id))

  monkeypatch.setattr(
    "app.api.incidents.create_gemini_client",
    lambda: httpx.AsyncClient(
      transport=httpx.MockTransport(handler),
      trust_env=False,
    ),
  )
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}"
    f"/investigation-runs/{run_id}/synthesis"
  )
  response = await client.post(endpoint, headers=_headers(owner))
  replay = await client.post(endpoint, headers=_headers(owner))

  assert response.status_code == 200
  assert replay.status_code == 200
  assert response.json() == replay.json()
  assert len(requests) == 1
  body = response.json()
  assert body["status"] == "succeeded"
  assert body["report"]["status"] == "conclusion"
  assert body["report"]["findings"][0]["evidence_ids"] == [str(evidence_id)]
  assert body["attempt_count"] == 1
  assert body["provider_attempts"] == 1
  assert body["input_tokens"] == 150
  assert body["output_tokens"] == 35

  status_response = await client.get(endpoint, headers=_headers(owner))
  assert status_response.status_code == 200
  assert status_response.json() == body

  run_response = await client.get(
    f"/projects/{project_id}/incidents/{incident_id}"
    f"/investigation-runs/{run_id}",
    headers=_headers(owner),
  )
  assert run_response.status_code == 200
  assert run_response.json()["synthesis_report"] == body["report"]


@pytest.mark.asyncio
async def test_synthesis_rejects_an_evidence_citation_outside_the_run(
  synthesis_client,
  monkeypatch,
):
  client, session_factory = synthesis_client
  owner = await _create_user(session_factory, "synthesis-invalid-citation")
  project_id, incident_id = await _create_incident(client, owner)
  run_id, _evidence_id = await _create_run(
    session_factory,
    project_id,
    incident_id,
  )
  foreign_id = uuid.uuid4()

  async def handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_candidate(foreign_id))

  monkeypatch.setattr(
    "app.api.incidents.create_gemini_client",
    lambda: httpx.AsyncClient(
      transport=httpx.MockTransport(handler),
      trust_env=False,
    ),
  )
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}"
    f"/investigation-runs/{run_id}/synthesis"
  )
  response = await client.post(endpoint, headers=_headers(owner))

  assert response.status_code == 502
  assert response.json()["detail"] == (
    "Gemini returned a citation outside this run's evidence."
  )
  status_response = await client.get(endpoint, headers=_headers(owner))
  assert status_response.json()["status"] == "failed"
  assert status_response.json()["failure_code"] == (
    "unsupported_evidence_citation"
  )


@pytest.mark.asyncio
async def test_synthesis_requires_project_access_and_explicit_enablement(
  synthesis_client,
  monkeypatch,
):
  client, session_factory = synthesis_client
  owner = await _create_user(session_factory, "synthesis-owner-access")
  outsider = await _create_user(session_factory, "synthesis-outsider-access")
  project_id, incident_id = await _create_incident(client, owner)
  run_id, _evidence_id = await _create_run(
    session_factory,
    project_id,
    incident_id,
  )
  endpoint = (
    f"/projects/{project_id}/incidents/{incident_id}"
    f"/investigation-runs/{run_id}/synthesis"
  )

  monkeypatch.setattr(settings, "GEMINI_SYNTHESIS_ENABLED", False)
  denied = await client.post(endpoint, headers=_headers(owner))
  assert denied.status_code == 503
  assert denied.json()["detail"] == (
    "AI synthesis is disabled by server configuration."
  )

  monkeypatch.setattr(settings, "GEMINI_SYNTHESIS_ENABLED", True)
  forbidden = await client.post(endpoint, headers=_headers(outsider))
  assert forbidden.status_code == 404
