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
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import auth, environment, membership, organisation, project, user
from app.db.base import Base
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.main import app
from app.services.organisation_service import create_organisation
from app.services import organisation_service
from app.utils.jwt import create_access_token


def _email() -> str:
  return f"org-{secrets.token_hex(12)}@example.com"


@pytest_asyncio.fixture
async def organisation_client(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'organisations.sqlite3'}",
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

  transport = ASGITransport(app=app, client=("198.51.100.25", 40000))
  async with AsyncClient(
    transport=transport,
    base_url="http://testserver",
  ) as client:
    yield client, session_factory

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await engine.dispose()


async def _create_verified_user(
  session_factory: async_sessionmaker[AsyncSession],
) -> User:
  async with session_factory() as session:
    user = User(
      email=_email(),
      display_name="Organization Test",
      password_hash="unused-test-hash",
      email_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


def _auth_headers(user: User) -> dict[str, str]:
  return {"Authorization": f"Bearer {create_access_token(user.id)}"}


@pytest.mark.asyncio
async def test_create_organisation_makes_creator_its_owner(organisation_client):
  client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)

  response = await client.post(
    "/organisations",
    json={"name": "  Test organization  "},
    headers=_auth_headers(current_user),
  )

  assert response.status_code == 201
  created = response.json()
  assert created["name"] == "Test organization"
  assert created["role"] == "owner"
  assert created["owner_user_id"] == str(current_user.id)

  async with session_factory() as session:
    saved_organisation = await session.get(
      Organisation,
      uuid.UUID(created["id"]),
    )
    membership = await session.scalar(
      select(Membership).where(
        Membership.organisation_id == uuid.UUID(created["id"]),
        Membership.user_id == current_user.id,
      ),
    )

  assert saved_organisation is not None
  assert membership is not None
  assert membership.role == "owner"


@pytest.mark.asyncio
async def test_user_can_create_and_belong_to_multiple_organisations(
  organisation_client,
):
  client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)
  headers = _auth_headers(current_user)

  first = await client.post(
    "/organisations",
    json={"name": "First organization"},
    headers=headers,
  )
  second = await client.post(
    "/organisations",
    json={"name": "Second organization"},
    headers=headers,
  )
  listed = await client.get("/organisations", headers=headers)

  assert first.status_code == 201
  assert second.status_code == 201
  assert first.json()["id"] != second.json()["id"]
  assert {item["id"] for item in listed.json()} == {
    first.json()["id"],
    second.json()["id"],
  }


@pytest.mark.asyncio
async def test_organisation_name_is_globally_unique_case_insensitively(
  organisation_client,
):
  client, session_factory = organisation_client
  first_user = await _create_verified_user(session_factory)
  second_user = await _create_verified_user(session_factory)

  first = await client.post(
    "/organisations",
    json={"name": "Example Organization"},
    headers=_auth_headers(first_user),
  )
  duplicate = await client.post(
    "/organisations",
    json={"name": "  example organization  "},
    headers=_auth_headers(second_user),
  )

  assert first.status_code == 201
  assert duplicate.status_code == 409
  assert duplicate.json()["detail"] == (
    "An organisation with this name already exists"
  )


@pytest.mark.asyncio
async def test_database_rejects_duplicate_organisation_names(
  organisation_client,
):
  _client, session_factory = organisation_client
  first_user = await _create_verified_user(session_factory)
  second_user = await _create_verified_user(session_factory)

  async with session_factory() as session:
    session.add(
      Organisation(
        name="Database unique name",
        owner_user_id=first_user.id,
      ),
    )
    await session.flush()
    session.add(
      Organisation(
        name=" database unique name ",
        owner_user_id=second_user.id,
      ),
    )
    with pytest.raises(IntegrityError):
      await session.flush()
    await session.rollback()


@pytest.mark.asyncio
async def test_organisation_listing_is_isolated_by_authenticated_user(
  organisation_client,
):
  client, session_factory = organisation_client
  first_user = await _create_verified_user(session_factory)
  second_user = await _create_verified_user(session_factory)
  first = await client.post(
    "/organisations",
    json={"name": "First user's organization"},
    headers=_auth_headers(first_user),
  )
  second = await client.post(
    "/organisations",
    json={"name": "Second user's organization"},
    headers=_auth_headers(second_user),
  )

  first_list = await client.get(
    "/organisations",
    headers=_auth_headers(first_user),
  )
  second_list = await client.get(
    "/organisations",
    headers=_auth_headers(second_user),
  )

  assert {item["id"] for item in first_list.json()} == {first.json()["id"]}
  assert {item["id"] for item in second_list.json()} == {second.json()["id"]}


@pytest.mark.asyncio
async def test_auth_me_returns_user_and_organisation_memberships(
  organisation_client,
):
  client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)
  created = await client.post(
    "/organisations",
    json={"name": "Profile organization"},
    headers=_auth_headers(current_user),
  )

  response = await client.get(
    "/auth/me",
    headers=_auth_headers(current_user),
  )

  assert created.status_code == 201
  assert response.status_code == 200
  assert response.json()["id"] == str(current_user.id)
  assert response.json()["organisations"] == [
    {
      "id": created.json()["id"],
      "name": "Profile organization",
      "role": "owner",
    },
  ]


@pytest.mark.asyncio
async def test_auth_me_returns_empty_organisations_for_new_user(
  organisation_client,
):
  client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)

  response = await client.get(
    "/auth/me",
    headers=_auth_headers(current_user),
  )

  assert response.status_code == 200
  assert response.json()["id"] == str(current_user.id)
  assert response.json()["organisations"] == []


@pytest.mark.asyncio
async def test_organisation_endpoints_reject_unauthenticated_requests(
  organisation_client,
):
  client, _session_factory = organisation_client

  created = await client.post(
    "/organisations",
    json={"name": "Private organization"},
  )
  listed = await client.get("/organisations")

  assert created.status_code == 401
  assert listed.status_code == 401


@pytest.mark.asyncio
async def test_legacy_bootstrap_endpoint_is_removed(organisation_client):
  client, _session_factory = organisation_client

  response = await client.post(
    "/organisations/bootstrap",
    json={"name": "Bootstrap organization"},
  )

  assert response.status_code == 404


@pytest.mark.asyncio
async def test_organisation_invitation_acceptance_adds_invited_member(
  organisation_client,
  monkeypatch,
):
  client, session_factory = organisation_client
  owner = await _create_verified_user(session_factory)
  invitee = await _create_verified_user(session_factory)
  async with session_factory() as session:
    organisation = await create_organisation(
      session,
      owner,
      "Invitation organization",
    )
  sent_emails: list[tuple[str, str, str]] = []

  async def allow_invitation_rate_limit(*_args, **_kwargs) -> None:
    return None

  async def capture_email(
    recipient: str,
    subject: str,
    body: str,
  ) -> None:
    sent_emails.append((recipient, subject, body))

  app.dependency_overrides[get_redis] = lambda: None
  monkeypatch.setattr(
    organisation_service,
    "bump_rate_limit",
    allow_invitation_rate_limit,
  )
  monkeypatch.setattr(organisation_service, "send_email", capture_email)

  invited = await client.post(
    f"/organisations/{organisation.id}/invitations",
    json={"email": invitee.email, "role": "member"},
    headers=_auth_headers(owner),
  )
  assert invited.status_code == 202
  assert sent_emails[0][0] == invitee.email
  resent = await client.post(
    f"/organisations/{organisation.id}/invitations",
    json={"email": invitee.email, "role": "member"},
    headers=_auth_headers(owner),
  )
  assert resent.status_code == 202
  assert len(sent_emails) == 2
  assert sent_emails[1][0] == invitee.email

  accept_url = next(
    line for line in sent_emails[0][2].splitlines()
    if "accept-invitation?" in line
  )
  old_token = parse_qs(urlparse(accept_url).query)["token"][0]
  old_token_response = await client.post(
    "/organisations/invitations/accept",
    json={"token": old_token},
    headers=_auth_headers(invitee),
  )
  assert old_token_response.status_code == 403

  resent_accept_url = next(
    line for line in sent_emails[1][2].splitlines()
    if "accept-invitation?" in line
  )
  new_token = parse_qs(urlparse(resent_accept_url).query)["token"][0]
  accepted = await client.post(
    "/organisations/invitations/accept",
    json={"token": new_token},
    headers=_auth_headers(invitee),
  )

  assert accepted.status_code == 200
  assert accepted.json()["organisation_id"] == str(organisation.id)
  assert accepted.json()["role"] == "member"
  invited_organisations = await client.get(
    "/organisations",
    headers=_auth_headers(invitee),
  )
  assert [item["id"] for item in invited_organisations.json()] == [
    str(organisation.id),
  ]


@pytest.mark.asyncio
async def test_organisation_invitation_requires_the_invited_account(
  organisation_client,
  monkeypatch,
):
  client, session_factory = organisation_client
  owner = await _create_verified_user(session_factory)
  invitee = await _create_verified_user(session_factory)
  another_user = await _create_verified_user(session_factory)
  async with session_factory() as session:
    organisation = await create_organisation(
      session,
      owner,
      "Account-bound invitation organization",
    )
  sent_bodies: list[str] = []

  async def allow_invitation_rate_limit(*_args, **_kwargs) -> None:
    return None

  async def capture_email(_recipient: str, _subject: str, body: str) -> None:
    sent_bodies.append(body)

  app.dependency_overrides[get_redis] = lambda: None
  monkeypatch.setattr(
    organisation_service,
    "bump_rate_limit",
    allow_invitation_rate_limit,
  )
  monkeypatch.setattr(organisation_service, "send_email", capture_email)

  invited = await client.post(
    f"/organisations/{organisation.id}/invitations",
    json={"email": invitee.email, "role": "member"},
    headers=_auth_headers(owner),
  )
  assert invited.status_code == 202

  accept_url = next(
    line for line in sent_bodies[0].splitlines()
    if "accept-invitation?" in line
  )
  token = parse_qs(urlparse(accept_url).query)["token"][0]

  wrong_account = await client.post(
    "/organisations/invitations/accept",
    json={"token": token},
    headers=_auth_headers(another_user),
  )
  assert wrong_account.status_code == 403
  assert wrong_account.json()["detail"] == "Invitation is invalid or expired"

  accepted = await client.post(
    "/organisations/invitations/accept",
    json={"token": token},
    headers=_auth_headers(invitee),
  )
  assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_organisation_invitation_can_be_sent_before_account_signup(
  organisation_client,
  monkeypatch,
):
  client, session_factory = organisation_client
  owner = await _create_verified_user(session_factory)
  invitee_email = _email()
  async with session_factory() as session:
    organisation = await create_organisation(
      session,
      owner,
      "Pre-signup invitation organization",
    )
  sent_emails: list[tuple[str, str, str]] = []

  async def allow_invitation_rate_limit(*_args, **_kwargs) -> None:
    return None

  async def capture_email(
    recipient: str,
    subject: str,
    body: str,
  ) -> None:
    sent_emails.append((recipient, subject, body))

  app.dependency_overrides[get_redis] = lambda: None
  monkeypatch.setattr(
    organisation_service,
    "bump_rate_limit",
    allow_invitation_rate_limit,
  )
  monkeypatch.setattr(organisation_service, "send_email", capture_email)

  invited = await client.post(
    f"/organisations/{organisation.id}/invitations",
    json={"email": invitee_email, "role": "member"},
    headers=_auth_headers(owner),
  )

  assert invited.status_code == 202
  assert sent_emails[0][0] == invitee_email

  accept_url = next(
    line for line in sent_emails[0][2].splitlines()
    if "accept-invitation?" in line
  )
  token = parse_qs(urlparse(accept_url).query)["token"][0]
  invitee = User(
    email=invitee_email,
    display_name="New invitation recipient",
    password_hash="unused-test-hash",
    email_verified=True,
  )
  async with session_factory() as session:
    session.add(invitee)
    await session.commit()

  accepted = await client.post(
    "/organisations/invitations/accept",
    json={"token": token},
    headers=_auth_headers(invitee),
  )

  assert accepted.status_code == 200
  assert accepted.json()["organisation_id"] == str(organisation.id)


@pytest.mark.asyncio
async def test_organisation_name_must_not_be_blank(organisation_client):
  client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)

  response = await client.post(
    "/organisations",
    json={"name": "   "},
    headers=_auth_headers(current_user),
  )

  assert response.status_code == 422


@pytest.mark.asyncio
async def test_database_rejects_duplicate_memberships_and_multiple_owners(
  organisation_client,
):
  _client, session_factory = organisation_client
  first_user = await _create_verified_user(session_factory)
  second_user = await _create_verified_user(session_factory)

  async with session_factory() as session:
    target = Organisation(
      name="Constraint test",
      owner_user_id=first_user.id,
    )
    session.add(target)
    await session.flush()
    session.add(
      Membership(
        organisation_id=target.id,
        user_id=first_user.id,
        role="owner",
      ),
    )
    await session.commit()
    organisation_id = target.id

  async with session_factory() as session:
    session.add(
      Membership(
        organisation_id=organisation_id,
        user_id=first_user.id,
        role="member",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.commit()
    await session.rollback()

  async with session_factory() as session:
    session.add(
      Membership(
        organisation_id=organisation_id,
        user_id=second_user.id,
        role="owner",
      ),
    )
    with pytest.raises(IntegrityError):
      await session.commit()
    await session.rollback()


@pytest.mark.asyncio
async def test_failed_initial_membership_rolls_back_organisation(
  organisation_client,
  monkeypatch,
):
  _client, session_factory = organisation_client
  current_user = await _create_verified_user(session_factory)

  async with session_factory() as session:
    original_flush = AsyncSession.flush
    flush_count = 0

    async def fail_membership_flush(self, *args, **kwargs):
      nonlocal flush_count
      flush_count += 1
      if flush_count == 2:
        raise RuntimeError("simulated membership insert failure")
      return await original_flush(self, *args, **kwargs)

    monkeypatch.setattr(AsyncSession, "flush", fail_membership_flush)
    with pytest.raises(RuntimeError, match="simulated membership insert failure"):
      await create_organisation(session, current_user, "Must roll back")

  async with session_factory() as session:
    saved = await session.scalar(
      select(Organisation).where(Organisation.name == "Must roll back"),
    )

  assert saved is None
