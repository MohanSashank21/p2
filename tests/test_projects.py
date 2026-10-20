import os
import secrets
import uuid
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import (
  auth,
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
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.project import Project
from app.db.project_membership import ProjectMembership
from app.db.user import User
from app.db.redis import get_redis
from app.main import app
from app.services import project_service
from app.services.organisation_service import create_organisation
from app.utils.jwt import create_access_token


def _email() -> str:
  return f"project-{secrets.token_hex(12)}@example.com"


@pytest_asyncio.fixture
async def project_client(tmp_path, monkeypatch):
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
  redis = Redis.from_url(
    os.environ["REDIS_URL"],
    db=15,
    encoding="utf-8",
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2,
  )
  await redis.ping()
  sent_emails: list[tuple[str, str, str]] = []

  async def fake_send_email(
    recipient: str,
    subject: str,
    body: str,
  ) -> None:
    sent_emails.append((recipient, subject, body))

  async def override_database():
    async with session_factory() as session:
      yield session

  original_overrides = app.dependency_overrides.copy()
  app.dependency_overrides[get_db] = override_database
  app.dependency_overrides[get_redis] = lambda: redis
  monkeypatch.setattr(project_service, "send_email", fake_send_email)

  transport = ASGITransport(
    app=app,
    client=(f"test-{uuid.uuid4().hex}", 40000),
  )
  async with AsyncClient(
    transport=transport,
    base_url="http://testserver",
  ) as client:
    yield client, session_factory, sent_emails

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await redis.aclose()
  await engine.dispose()


async def _create_user(
  session_factory: async_sessionmaker[AsyncSession],
) -> User:
  async with session_factory() as session:
    user = User(
      email=_email(),
      display_name="Project Test",
      password_hash="unused-test-hash",
      email_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


async def _create_organisation(
  session_factory: async_sessionmaker[AsyncSession],
  owner: User,
  name: str = "Project organization",
) -> Organisation:
  async with session_factory() as session:
    return await create_organisation(session, owner, name)


async def _add_organisation_member(
  session_factory: async_sessionmaker[AsyncSession],
  organisation_id: uuid.UUID,
  member: User,
) -> None:
  async with session_factory() as session:
    session.add(
      Membership(
        organisation_id=organisation_id,
        user_id=member.id,
        role="member",
      ),
    )
    await session.commit()


def _auth_headers(user: User) -> dict[str, str]:
  return {"Authorization": f"Bearer {create_access_token(user.id)}"}


def _invitation_token(sent_emails: list[tuple[str, str, str]]) -> str:
  assert sent_emails
  accept_url = next(
    line
    for line in sent_emails[-1][2].splitlines()
    if "accept-project-invitation?" in line
  )
  query = urlparse(accept_url).query
  return parse_qs(query)["token"][0]


async def _propose_project(
  client: AsyncClient,
  organisation_id: uuid.UUID,
  owner: User,
  manager: User,
  name: str = "Project A",
):
  return await client.post(
    f"/organisations/{organisation_id}/projects",
    json={
      "name": name,
      "description": "Project description",
      "manager_user_id": str(manager.id),
    },
    headers=_auth_headers(owner),
  )


@pytest.mark.asyncio
async def test_project_is_created_only_after_manager_accepts(project_client):
  client, session_factory, sent_emails = project_client
  owner = await _create_user(session_factory)
  manager = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  await _add_organisation_member(session_factory, organisation.id, manager)

  invitation = await _propose_project(
    client,
    organisation.id,
    owner,
    manager,
  )
  assert invitation.status_code == 202
  assert sent_emails[-1][0] == manager.email

  async with session_factory() as session:
    assert await session.scalar(select(Project.id)) is None

  accepted = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(manager),
  )
  assert accepted.status_code == 200
  project_response = accepted.json()
  assert project_response["name"] == "Project A"
  assert project_response["role"] == "manager"

  async with session_factory() as session:
    saved_project = await session.get(
      Project,
      uuid.UUID(project_response["id"]),
    )
    saved_membership = await session.scalar(
      select(ProjectMembership).where(
        ProjectMembership.project_id == uuid.UUID(project_response["id"]),
        ProjectMembership.user_id == manager.id,
      ),
    )

  assert saved_project is not None
  assert saved_membership is not None
  assert saved_membership.role == "manager"

  manager_projects = await client.get(
    f"/organisations/{organisation.id}/projects",
    headers=_auth_headers(manager),
  )
  owner_projects = await client.get(
    f"/organisations/{organisation.id}/projects",
    headers=_auth_headers(owner),
  )
  assert [item["id"] for item in manager_projects.json()] == [
    project_response["id"],
  ]
  assert owner_projects.json()[0]["role"] == "owner"


@pytest.mark.asyncio
async def test_one_user_can_hold_different_project_roles_and_org_owner(
  project_client,
):
  client, session_factory, sent_emails = project_client
  owner = await _create_user(session_factory)
  project_manager = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  await _add_organisation_member(
    session_factory,
    organisation.id,
    project_manager,
  )

  manager_proposal = await _propose_project(
    client,
    organisation.id,
    owner,
    owner,
    "Managed project",
  )
  manager_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(owner),
  )
  assert manager_proposal.status_code == 202
  assert manager_acceptance.status_code == 200
  assert manager_acceptance.json()["role"] == "manager"

  worker_proposal = await _propose_project(
    client,
    organisation.id,
    owner,
    project_manager,
    "Worker project",
  )
  project_manager_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(project_manager),
  )
  assert worker_proposal.status_code == 202
  assert project_manager_acceptance.status_code == 200
  assert project_manager_acceptance.json()["role"] == "manager"

  worker_invitation = await client.post(
    f"/organisations/{organisation.id}/projects/{project_manager_acceptance.json()['id']}/worker-invitations",
    json={"user_id": str(owner.id)},
    headers=_auth_headers(project_manager),
  )
  assert worker_invitation.status_code == 202
  worker_role_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(owner),
  )
  assert worker_role_acceptance.status_code == 200
  assert worker_role_acceptance.json()["role"] == "worker"

  projects = await client.get(
    f"/organisations/{organisation.id}/projects",
    headers=_auth_headers(owner),
  )
  roles_by_name = {item["name"]: item["role"] for item in projects.json()}
  assert roles_by_name == {
    "Managed project": "manager",
    "Worker project": "worker",
  }


@pytest.mark.asyncio
async def test_manager_invites_worker_to_project_and_worker_accepts(
  project_client,
):
  client, session_factory, sent_emails = project_client
  owner = await _create_user(session_factory)
  manager = await _create_user(session_factory)
  worker = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  for member in (manager, worker):
    await _add_organisation_member(session_factory, organisation.id, member)

  proposed = await _propose_project(
    client,
    organisation.id,
    owner,
    manager,
  )
  assert proposed.status_code == 202
  manager_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(manager),
  )
  assert manager_acceptance.status_code == 200
  project_id = manager_acceptance.json()["id"]

  worker_invitation = await client.post(
    f"/organisations/{organisation.id}/projects/{project_id}/worker-invitations",
    json={"user_id": str(worker.id)},
    headers=_auth_headers(manager),
  )
  assert worker_invitation.status_code == 202
  assert sent_emails[-1][0] == worker.email

  async with session_factory() as session:
    assert await session.scalar(
      select(ProjectMembership.id).where(
        ProjectMembership.project_id == uuid.UUID(project_id),
        ProjectMembership.user_id == worker.id,
      ),
    ) is None

  worker_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(worker),
  )
  assert worker_acceptance.status_code == 200
  assert worker_acceptance.json()["role"] == "worker"

  worker_projects = await client.get(
    f"/organisations/{organisation.id}/projects",
    headers=_auth_headers(worker),
  )
  assert [item["id"] for item in worker_projects.json()] == [project_id]
  assert worker_projects.json()[0]["role"] == "worker"


@pytest.mark.asyncio
async def test_project_invites_require_existing_verified_org_members(
  project_client,
):
  client, session_factory, _sent_emails = project_client
  owner = await _create_user(session_factory)
  non_member = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)

  response = await _propose_project(
    client,
    organisation.id,
    owner,
    non_member,
  )

  assert response.status_code == 400


@pytest.mark.asyncio
async def test_worker_invitation_rejects_non_members_and_duplicate_members(
  project_client,
):
  client, session_factory, sent_emails = project_client
  owner = await _create_user(session_factory)
  manager = await _create_user(session_factory)
  worker = await _create_user(session_factory)
  outsider = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  await _add_organisation_member(session_factory, organisation.id, manager)
  await _add_organisation_member(session_factory, organisation.id, worker)

  proposal = await _propose_project(
    client,
    organisation.id,
    owner,
    manager,
  )
  manager_accepted = await client.post(
    "/project-invitations/accept",
    json={"token": _invitation_token(sent_emails)},
    headers=_auth_headers(manager),
  )
  project_id = manager_accepted.json()["id"]

  outsider_response = await client.post(
    f"/organisations/{organisation.id}/projects/{project_id}/worker-invitations",
    json={"user_id": str(outsider.id)},
    headers=_auth_headers(manager),
  )
  assert outsider_response.status_code == 400

  first_invitation = await client.post(
    f"/organisations/{organisation.id}/projects/{project_id}/worker-invitations",
    json={"user_id": str(worker.id)},
    headers=_auth_headers(manager),
  )
  duplicate_invitation = await client.post(
    f"/organisations/{organisation.id}/projects/{project_id}/worker-invitations",
    json={"user_id": str(worker.id)},
    headers=_auth_headers(manager),
  )
  assert first_invitation.status_code == 202
  assert duplicate_invitation.status_code == 409


@pytest.mark.asyncio
async def test_project_invitation_is_bound_to_invited_identity_and_single_use(
  project_client,
):
  client, session_factory, sent_emails = project_client
  owner = await _create_user(session_factory)
  manager = await _create_user(session_factory)
  another_member = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  await _add_organisation_member(session_factory, organisation.id, manager)
  await _add_organisation_member(session_factory, organisation.id, another_member)

  invitation = await _propose_project(
    client,
    organisation.id,
    owner,
    manager,
  )
  token = _invitation_token(sent_emails)
  wrong_user_acceptance = await client.post(
    "/project-invitations/accept",
    json={"token": token},
    headers=_auth_headers(another_member),
  )
  accepted = await client.post(
    "/project-invitations/accept",
    json={"token": token},
    headers=_auth_headers(manager),
  )
  replayed = await client.post(
    "/project-invitations/accept",
    json={"token": token},
    headers=_auth_headers(manager),
  )

  assert invitation.status_code == 202
  assert wrong_user_acceptance.status_code == 403
  assert accepted.status_code == 200
  assert replayed.status_code == 403


@pytest.mark.asyncio
async def test_project_endpoints_require_authentication(project_client):
  client, session_factory, _sent_emails = project_client
  owner = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)

  response = await client.get(
    f"/organisations/{organisation.id}/projects",
  )

  assert response.status_code == 401


@pytest.mark.asyncio
async def test_project_membership_constraints_enforce_scope_and_uniqueness(
  project_client,
):
  _client, session_factory, _sent_emails = project_client
  owner = await _create_user(session_factory)
  member = await _create_user(session_factory)
  outsider = await _create_user(session_factory)
  organisation = await _create_organisation(session_factory, owner)
  other_organisation = await _create_organisation(
    session_factory,
    outsider,
    "Other organization",
  )
  await _add_organisation_member(session_factory, organisation.id, member)

  async with session_factory() as session:
    project = Project(
      organisation_id=organisation.id,
      name="Constraint project",
    )
    session.add(project)
    await session.commit()
    project_id = project.id

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        organisation_id=organisation.id,
        user_id=member.id,
        role="worker",
      ),
    )
    await session.commit()

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        organisation_id=organisation.id,
        user_id=member.id,
        role="manager",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.commit()
    await session.rollback()

  async with session_factory() as session:
    session.add(
      ProjectMembership(
        project_id=project_id,
        organisation_id=organisation.id,
        user_id=outsider.id,
        role="worker",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.commit()
    await session.rollback()

  assert other_organisation.id != organisation.id
