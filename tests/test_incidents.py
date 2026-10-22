import os
import secrets
import uuid

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

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
from app.db.incident_source import IncidentSource
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
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
