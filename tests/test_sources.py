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
  incident_source,
  project_membership,
  user,
)
from app.db.base import Base
from app.db.database import get_db
from app.db.environment import Environment
from app.db.incident_source import IncidentSource, SourceEvent
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.utils.jwt import create_access_token


def test_webhook_openapi_documents_body_and_source_bearer_credential():
  operation = app.openapi()["paths"]["/webhooks/sources/{source_id}"]["post"]

  request_body = operation["requestBody"]
  assert request_body["required"] is True
  schema = request_body["content"]["application/json"]["schema"]
  assert schema["properties"]["title"]["type"] == "string"
  assert schema["required"] == ["title"]
  assert request_body["content"]["application/json"]["example"]["title"]

  assert operation["security"] == [{"SourceCredential": []}]
  security_scheme = app.openapi()["components"]["securitySchemes"]["SourceCredential"]
  assert security_scheme == {
    "type": "http",
    "scheme": "bearer",
    "description": (
      "Bearer credential returned when the project source is created."
    ),
  }


class FakeRedis:
  def __init__(self):
    self.counts: dict[str, int] = {}

  async def eval(self, _script: str, _key_count: int, key: str, *_args):
    self.counts[key] = self.counts.get(key, 0) + 1
    return self.counts[key]


@pytest_asyncio.fixture
async def source_client(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'sources.sqlite3'}",
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

  transport = ASGITransport(app=app, client=(f"source-test-{uuid.uuid4().hex}", 40000))
  async with AsyncClient(transport=transport, base_url="http://testserver") as client:
    yield client, session_factory, fake_redis

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await engine.dispose()


async def _create_user(
  session_factory: async_sessionmaker[AsyncSession],
  label: str,
) -> User:
  async with session_factory() as session:
    user = User(
      email=f"{label}-{secrets.token_hex(8)}@example.com",
      display_name=label,
      password_hash="test-hash",
      email_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


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


async def _create_member(
  session_factory: async_sessionmaker[AsyncSession],
  project_id: uuid.UUID,
  member: User,
) -> None:
  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        user_id=member.id,
        role="member",
      ),
    )
    await session.commit()


async def _create_source(
  client: AsyncClient,
  project_id: uuid.UUID,
  owner: User,
  *,
  name: str = "Production alerts",
  environment_id: uuid.UUID | None = None,
):
  return await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": name,
      "source_type": "generic_webhook",
      "environment_id": str(environment_id) if environment_id else None,
    },
    headers=_headers(owner),
  )


@pytest.mark.asyncio
async def test_source_creation_returns_one_time_credential_and_is_project_scoped(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "owner")
  member = await _create_user(session_factory, "member")
  outsider = await _create_user(session_factory, "outsider")
  project_id = await _create_project(client, owner, "Payments")
  await _create_member(session_factory, project_id, member)

  created = await _create_source(client, project_id, owner)
  assert created.status_code == 201
  payload = created.json()
  credential = payload["credential"]
  source_id = uuid.UUID(payload["id"])
  assert payload["project_id"] == str(project_id)
  assert payload["enabled"] is True

  listed = await client.get(
    f"/projects/{project_id}/sources",
    headers=_headers(member),
  )
  assert listed.status_code == 200
  assert len(listed.json()) == 1
  assert "credential" not in listed.json()[0]

  member_create = await _create_source(client, project_id, member, name="member")
  outsider_list = await client.get(
    f"/projects/{project_id}/sources",
    headers=_headers(outsider),
  )
  assert member_create.status_code == 403
  assert outsider_list.status_code == 404

  async with session_factory() as session:
    source = await session.get(IncidentSource, source_id)
  assert source is not None
  assert source.credential_hash != credential
  assert len(source.credential_hash) == 64


@pytest.mark.asyncio
async def test_source_environment_must_belong_to_selected_project(source_client):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "owner")
  first_project = await _create_project(client, owner, "Project One")
  second_project = await _create_project(client, owner, "Project Two")
  async with session_factory() as session:
    environment = Environment(
      project_id=second_project,
      name="Production",
      environment_type="production",
    )
    session.add(environment)
    await session.commit()
    environment_id = environment.id

  response = await _create_source(
    client,
    first_project,
    owner,
    environment_id=environment_id,
  )
  assert response.status_code == 404


@pytest.mark.asyncio
async def test_webhook_persists_project_event_and_duplicate_delivery_is_idempotent(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "Payments")
  source = await _create_source(client, project_id, owner)
  credential = source.json()["credential"]
  source_id = source.json()["id"]
  body = {
    "event_id": "alert-2026-01",
    "event_type": "application_error",
    "title": "Checkout requests are failing",
    "description": "Elevated HTTP 500 rate",
    "severity": "critical",
    "labels": {"service": "checkout", "environment": "production"},
    "raw": {"count": 23, "sample": "database timeout"},
  }
  headers = {"Authorization": f"Bearer {credential}"}

  accepted = await client.post(
    f"/webhooks/sources/{source_id}",
    json=body,
    headers=headers,
  )
  repeated = await client.post(
    f"/webhooks/sources/{source_id}",
    json=body,
    headers=headers,
  )

  assert accepted.status_code == 201
  assert accepted.json()["duplicate"] is False
  assert accepted.json()["event"]["project_id"] == str(project_id)
  assert repeated.status_code == 200
  assert repeated.json()["duplicate"] is True
  assert repeated.json()["event"]["id"] == accepted.json()["event"]["id"]

  listed = await client.get(
    f"/projects/{project_id}/events",
    headers=_headers(owner),
  )
  event_id = accepted.json()["event"]["id"]
  detail = await client.get(
    f"/projects/{project_id}/events/{event_id}",
    headers=_headers(owner),
  )
  assert listed.status_code == 200
  assert len(listed.json()) == 1
  assert detail.status_code == 200
  assert detail.json()["original_payload"] == body

  async with session_factory() as session:
    rows = list(
      await session.scalars(
        select(SourceEvent).where(SourceEvent.project_id == project_id),
      ),
    )
  assert len(rows) == 1
  assert rows[0].source_id == uuid.UUID(source_id)
  assert rows[0].environment_id is None


@pytest.mark.asyncio
async def test_webhook_requires_source_credential_and_disable_revokes_access(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "Payments")
  source = await _create_source(client, project_id, owner)
  source_id = source.json()["id"]
  old_credential = source.json()["credential"]
  body = {"title": "Host is unreachable"}

  missing = await client.post(f"/webhooks/sources/{source_id}", json=body)
  invalid = await client.post(
    f"/webhooks/sources/{source_id}",
    json=body,
    headers={"Authorization": "Bearer wrong"},
  )
  assert missing.status_code == 401
  assert invalid.status_code == 401

  rotated = await client.post(
    f"/projects/{project_id}/sources/{source_id}/rotate-credential",
    headers=_headers(owner),
  )
  assert rotated.status_code == 200
  new_credential = rotated.json()["credential"]
  old_token = await client.post(
    f"/webhooks/sources/{source_id}",
    json=body,
    headers={"Authorization": f"Bearer {old_credential}"},
  )
  new_token = await client.post(
    f"/webhooks/sources/{source_id}",
    json=body,
    headers={"Authorization": f"Bearer {new_credential}"},
  )
  assert old_token.status_code == 401
  assert new_token.status_code == 201

  disabled = await client.post(
    f"/projects/{project_id}/sources/{source_id}/disable",
    headers=_headers(owner),
  )
  after_disable = await client.post(
    f"/webhooks/sources/{source_id}",
    json={"title": "Another failure"},
    headers={"Authorization": f"Bearer {new_credential}"},
  )
  assert disabled.status_code == 200
  assert disabled.json()["enabled"] is False
  assert after_disable.status_code == 401

  async with session_factory() as session:
    saved = await session.get(IncidentSource, uuid.UUID(source_id))
  assert saved is not None
  assert saved.enabled is False


@pytest.mark.asyncio
async def test_received_events_are_not_visible_across_project_boundary(source_client):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "owner")
  outsider = await _create_user(session_factory, "outsider")
  project_id = await _create_project(client, owner, "Private project")
  other_project_id = await _create_project(client, outsider, "Other project")
  source = await _create_source(client, project_id, owner)
  event_response = await client.post(
    f"/webhooks/sources/{source.json()['id']}",
    json={"title": "Database unavailable"},
    headers={"Authorization": f"Bearer {source.json()['credential']}"},
  )
  event_id = event_response.json()["event"]["id"]

  listed = await client.get(
    f"/projects/{other_project_id}/events",
    headers=_headers(outsider),
  )
  detail = await client.get(
    f"/projects/{other_project_id}/events/{event_id}",
    headers=_headers(outsider),
  )
  assert listed.status_code == 200
  assert listed.json() == []
  assert detail.status_code == 404


@pytest.mark.asyncio
async def test_source_event_payload_is_bounded_and_rate_limited_per_source(
  source_client,
):
  client, session_factory, fake_redis = source_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "Payments")
  source = await _create_source(client, project_id, owner)
  source_id = source.json()["id"]
  credential = source.json()["credential"]
  url = f"/webhooks/sources/{source_id}"
  headers = {"Authorization": f"Bearer {credential}"}

  oversized = await client.post(
    url,
    content=b'{"title":"' + b"x" * 1_048_576 + b'"}',
    headers={**headers, "Content-Type": "application/json"},
  )
  assert oversized.status_code == 413

  rate_limit_key = next(iter(fake_redis.counts))
  fake_redis.counts[rate_limit_key] = 120
  limited = await client.post(url, json={"title": "Over limit"}, headers=headers)
  assert limited.status_code == 429
  assert limited.headers["Retry-After"] == "60"
