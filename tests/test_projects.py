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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import (
  auth,
  email_outbox,
  environment,
  membership,
  organisation,
  project,
  project_invitation,
  project_membership,
  user,
)
from app.db.base import Base
from app.db.database import get_db
from app.db.environment import Environment
from app.db.project import Project
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.utils.jwt import create_access_token


def _email() -> str:
  return f"project-{secrets.token_hex(12)}@example.com"


@pytest_asyncio.fixture
async def project_client(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'projects.sqlite3'}",
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

  async def override_database():
    async with session_factory() as session:
      yield session

  original_overrides = app.dependency_overrides.copy()
  app.dependency_overrides[get_db] = override_database
  app.dependency_overrides.pop(get_redis, None)

  transport = ASGITransport(
    app=app,
    client=(f"test-{uuid.uuid4().hex}", 40000),
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
) -> User:
  async with session_factory() as session:
    created = User(
      email=_email(),
      display_name="Project Test",
      password_hash="unused-test-hash",
      email_verified=True,
    )
    session.add(created)
    await session.commit()
    return created


def _auth_headers(user: User) -> dict[str, str]:
  return {"Authorization": f"Bearer {create_access_token(user.id)}"}


async def _create_project(
  client: AsyncClient,
  user: User,
  name: str,
):
  return await client.post(
    "/projects",
    json={"name": name, "description": f"{name} description"},
    headers=_auth_headers(user),
  )


@pytest.mark.asyncio
async def test_project_creator_becomes_owner_and_projects_are_top_level(
  project_client,
):
  client, session_factory = project_client
  owner = await _create_user(session_factory)

  response = await _create_project(client, owner, "  Project A  ")

  assert response.status_code == 201
  payload = response.json()
  assert payload["name"] == "Project A"
  assert payload["role"] == "owner"
  assert "organisation_id" not in payload

  async with session_factory() as session:
    saved_project = await session.get(Project, uuid.UUID(payload["id"]))
    membership = await session.scalar(
      select(ProjectMembership).where(
        ProjectMembership.project_id == uuid.UUID(payload["id"]),
        ProjectMembership.user_id == owner.id,
      ),
    )

  assert saved_project is not None
  assert saved_project.legacy_organisation_id is None
  assert membership is not None
  assert membership.role == "owner"


@pytest.mark.asyncio
async def test_user_can_create_and_list_multiple_projects(project_client):
  client, session_factory = project_client
  owner = await _create_user(session_factory)

  first = await _create_project(client, owner, "First")
  second = await _create_project(client, owner, "Second")
  listed = await client.get("/projects", headers=_auth_headers(owner))

  assert first.status_code == 201
  assert second.status_code == 201
  assert first.json()["id"] != second.json()["id"]
  assert {item["name"] for item in listed.json()} == {"First", "Second"}
  assert {item["role"] for item in listed.json()} == {"owner"}


@pytest.mark.asyncio
async def test_projects_are_isolated_between_users(project_client):
  client, session_factory = project_client
  owner = await _create_user(session_factory)
  outsider = await _create_user(session_factory)
  created = await _create_project(client, owner, "Private")
  project_id = created.json()["id"]

  listed = await client.get("/projects", headers=_auth_headers(outsider))
  retrieved = await client.get(
    f"/projects/{project_id}",
    headers=_auth_headers(outsider),
  )
  updated = await client.patch(
    f"/projects/{project_id}",
    json={"name": "Stolen"},
    headers=_auth_headers(outsider),
  )
  deleted = await client.delete(
    f"/projects/{project_id}",
    headers=_auth_headers(outsider),
  )

  assert listed.status_code == 200
  assert listed.json() == []
  assert retrieved.status_code == 404
  assert updated.status_code == 404
  assert deleted.status_code == 404

  async with session_factory() as session:
    saved_project = await session.get(Project, uuid.UUID(project_id))
  assert saved_project is not None
  assert saved_project.name == "Private"


@pytest.mark.asyncio
async def test_member_can_read_but_not_update_or_delete_project(project_client):
  client, session_factory = project_client
  owner = await _create_user(session_factory)
  member = await _create_user(session_factory)
  created = await _create_project(client, owner, "Shared")
  project_id = uuid.UUID(created.json()["id"])

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        user_id=member.id,
        role="member",
      ),
    )
    await session.commit()

  listed = await client.get("/projects", headers=_auth_headers(member))
  retrieved = await client.get(
    f"/projects/{project_id}",
    headers=_auth_headers(member),
  )
  updated = await client.patch(
    f"/projects/{project_id}",
    json={"name": "Changed"},
    headers=_auth_headers(member),
  )
  deleted = await client.delete(
    f"/projects/{project_id}",
    headers=_auth_headers(member),
  )

  assert listed.status_code == 200
  assert listed.json()[0]["role"] == "member"
  assert retrieved.status_code == 200
  assert retrieved.json()["role"] == "member"
  assert updated.status_code == 403
  assert deleted.status_code == 403


@pytest.mark.asyncio
async def test_owner_can_update_and_delete_project_resources(project_client):
  client, session_factory = project_client
  owner = await _create_user(session_factory)
  created = await _create_project(client, owner, "Before")
  project_id = uuid.UUID(created.json()["id"])
  async with session_factory() as session:
    session.add(
      Environment(
        project_id=project_id,
        name="Production",
        environment_type="production",
      ),
    )
    await session.commit()

  updated = await client.patch(
    f"/projects/{project_id}",
    json={"name": "After", "description": None},
    headers=_auth_headers(owner),
  )
  retrieved = await client.get(
    f"/projects/{project_id}",
    headers=_auth_headers(owner),
  )
  deleted = await client.delete(
    f"/projects/{project_id}",
    headers=_auth_headers(owner),
  )

  assert updated.status_code == 200
  assert updated.json()["name"] == "After"
  assert updated.json()["description"] is None
  assert retrieved.json()["name"] == "After"
  assert deleted.status_code == 204
  async with session_factory() as session:
    assert await session.get(Project, project_id) is None
    assert await session.scalar(
      select(Environment.id).where(Environment.project_id == project_id),
    ) is None
    assert await session.scalar(
      select(ProjectMembership.id).where(
        ProjectMembership.project_id == project_id,
      ),
    ) is None


@pytest.mark.asyncio
async def test_project_membership_constraints_reject_duplicate_and_bad_role(
  project_client,
):
  client, session_factory = project_client
  owner = await _create_user(session_factory)
  created = await _create_project(client, owner, "Constrained")
  project_id = uuid.UUID(created.json()["id"])

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        user_id=owner.id,
        role="owner",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.flush()
    await session.rollback()

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        user_id=uuid.uuid4(),
        role="manager",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.flush()
    await session.rollback()


@pytest.mark.asyncio
async def test_project_endpoints_require_authentication(project_client):
  client, _session_factory = project_client

  created = await client.post("/projects", json={"name": "Unauthenticated"})
  listed = await client.get("/projects")

  assert created.status_code == 401
  assert listed.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_reports_project_memberships_without_organization_data(
  project_client,
):
  client, session_factory = project_client
  owner = await _create_user(session_factory)
  created = await _create_project(client, owner, "Profile Project")

  profile = await client.get("/auth/me", headers=_auth_headers(owner))

  assert profile.status_code == 200
  assert profile.json()["projects"] == [
    {
      "id": created.json()["id"],
      "name": "Profile Project",
      "role": "owner",
    },
  ]
  assert "organisations" not in profile.json()
