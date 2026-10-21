import os
import secrets

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import auth, environment, project, project_membership, user
from app.db.base import Base
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.core.exceptions import EmailDeliveryError
from app.services import auth_service
from app.utils.password import hash_password


def _email(purpose: str) -> str:
  return f"{purpose}-{secrets.token_hex(12)}@example.com"


def _refresh_cookie(response) -> str:
  token = response.cookies.get("opspilot_refresh")
  assert token
  return token


@pytest_asyncio.fixture
async def api_client(tmp_path, monkeypatch):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'auth-resend.sqlite3'}",
  )

  @event.listens_for(engine.sync_engine, "connect")
  def register_name_trim_function(connection, _connection_record):
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
  sent_emails: list[tuple[str, str]] = []

  async def fake_send_otp(recipient: str, code: str) -> None:
    sent_emails.append((recipient, code))

  async def override_database():
    async with session_factory() as session:
      yield session

  original_overrides = app.dependency_overrides.copy()
  app.dependency_overrides[get_db] = override_database
  app.dependency_overrides[get_redis] = lambda: redis
  monkeypatch.setattr(auth_service, "send_otp_email", fake_send_otp)

  transport = ASGITransport(
    app=app,
    client=(f"198.51.100.{secrets.randbelow(200) + 1}", 40000),
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


@pytest.mark.asyncio
async def test_resend_without_active_challenge_is_generic_and_sends_nothing(
  api_client,
):
  client, _session_factory, sent_emails = api_client

  response = await client.post(
    "/auth/otp/resend",
    json={"email": _email("missing"), "purpose": "register"},
  )

  assert response.status_code == 202
  assert response.json() == {
    "message": (
      "If your request is eligible, a verification code has been sent "
      "to you by email."
    ),
  }
  assert sent_emails == []


@pytest.mark.asyncio
async def test_registration_resend_replaces_active_code(api_client):
  client, _session_factory, sent_emails = api_client
  email = _email("register")

  started = await client.post(
    "/auth/register",
    json={
      "email": email,
      "display_name": "Registration Test",
      "password": "RegisterPass123!",
    },
  )
  assert started.status_code == 202
  initial_count = len(sent_emails)

  resent = await client.post(
    "/auth/otp/resend",
    json={"email": email, "purpose": "registration"},
  )
  assert resent.status_code == 202
  assert len(sent_emails) == initial_count + 1
  assert sent_emails[-1][0] == email

  verified = await client.post(
    "/auth/register/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert verified.status_code == 200


@pytest.mark.asyncio
async def test_resend_does_not_cross_otp_purposes(api_client):
  client, _session_factory, sent_emails = api_client
  email = _email("purpose")

  started = await client.post(
    "/auth/register",
    json={
      "email": email,
      "display_name": "Purpose Test",
      "password": "PurposePass123!",
    },
  )
  assert started.status_code == 202
  registration_code = sent_emails[-1][1]
  initial_count = len(sent_emails)

  wrong_purpose = await client.post(
    "/auth/otp/resend",
    json={"email": email, "purpose": "login"},
  )
  assert wrong_purpose.status_code == 202
  assert len(sent_emails) == initial_count

  verified = await client.post(
    "/auth/register/verify",
    json={"email": email, "code": registration_code},
  )
  assert verified.status_code == 200


@pytest.mark.asyncio
async def test_login_resend_replaces_active_code(api_client):
  client, session_factory, sent_emails = api_client
  email = _email("login")
  async with session_factory() as session:
    session.add(
      User(
        email=email,
        display_name="Login Test",
        password_hash=hash_password("LoginPass123!"),
        email_verified=True,
      ),
    )
    await session.commit()

  started = await client.post(
    "/auth/login",
    json={"email": email, "password": "LoginPass123!"},
  )
  assert started.status_code == 202
  initial_count = len(sent_emails)

  resent = await client.post(
    "/auth/otp/resend",
    json={"email": email, "purpose": "login"},
  )
  assert resent.status_code == 202
  assert len(sent_emails) == initial_count + 1
  assert sent_emails[-1][0] == email

  original_code = sent_emails[0][1]
  assert sent_emails[-1][1] != original_code
  original_code_response = await client.post(
    "/auth/login/verify",
    json={"email": email, "code": original_code},
  )
  assert original_code_response.status_code == 400

  verified = await client.post(
    "/auth/login/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert verified.status_code == 200


@pytest.mark.asyncio
async def test_password_reset_resend_replaces_active_code(api_client):
  client, session_factory, sent_emails = api_client
  email = _email("reset")
  async with session_factory() as session:
    session.add(
      User(
        email=email,
        display_name="Reset Test",
        password_hash=hash_password("ResetPass123!"),
        email_verified=True,
      ),
    )
    await session.commit()

  started = await client.post(
    "/auth/password/reset",
    json={"email": email},
  )
  assert started.status_code == 202
  initial_count = len(sent_emails)

  resent = await client.post(
    "/auth/otp/resend",
    json={"email": email, "purpose": "forgot_password"},
  )
  assert resent.status_code == 202
  assert len(sent_emails) == initial_count + 1
  assert sent_emails[-1][0] == email

  verified = await client.post(
    "/auth/password/reset/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert verified.status_code == 200
  assert verified.json()["reset_token"]


@pytest.mark.asyncio
async def test_password_reset_completes_and_allows_login_with_new_password(
  api_client,
):
  client, session_factory, sent_emails = api_client
  email = _email("reset-complete")
  async with session_factory() as session:
    session.add(
      User(
        email=email,
        display_name="Reset Complete",
        password_hash=hash_password("OriginalPass123!"),
        email_verified=True,
      ),
    )
    await session.commit()

  started = await client.post("/auth/password/reset", json={"email": email})
  assert started.status_code == 202
  verified = await client.post(
    "/auth/password/reset/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert verified.status_code == 200
  completed = await client.post(
    "/auth/password/reset/complete",
    json={
      "reset_token": verified.json()["reset_token"],
      "new_password": "ChangedPass456!",
    },
  )
  assert completed.status_code == 204

  login = await client.post(
    "/auth/login",
    json={"email": email, "password": "ChangedPass456!"},
  )
  assert login.status_code == 202
  login_verified = await client.post(
    "/auth/login/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert login_verified.status_code == 200


@pytest.mark.asyncio
async def test_password_change_revokes_refresh_and_keeps_access_token_valid(
  api_client,
):
  client, session_factory, sent_emails = api_client
  email = _email("password-change")
  async with session_factory() as session:
    session.add(
      User(
        email=email,
        display_name="Password Change",
        password_hash=hash_password("OriginalPass123!"),
        email_verified=True,
      ),
    )
    await session.commit()

  await client.post(
    "/auth/login",
    json={"email": email, "password": "OriginalPass123!"},
  )
  login_verified = await client.post(
    "/auth/login/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert login_verified.status_code == 200
  refresh_cookie = _refresh_cookie(login_verified)

  changed = await client.post(
    "/auth/password/change",
    headers={
      "Authorization": f"Bearer {login_verified.json()['access_token']}",
    },
    json={
      "current_password": "OriginalPass123!",
      "new_password": "ChangedPass456!",
    },
  )
  assert changed.status_code == 204

  refresh = await client.post(
    "/auth/refresh",
    headers={"Cookie": f"opspilot_refresh={refresh_cookie}"},
  )
  assert refresh.status_code == 401
  profile = await client.get(
    "/auth/me",
    headers={
      "Authorization": f"Bearer {login_verified.json()['access_token']}",
    },
  )
  assert profile.status_code == 200


@pytest.mark.asyncio
async def test_refresh_rotates_cookie_and_logout_revokes_replacement(
  api_client,
):
  client, session_factory, sent_emails = api_client
  email = _email("refresh")
  async with session_factory() as session:
    session.add(
      User(
        email=email,
        display_name="Refresh Test",
        password_hash=hash_password("RefreshPass123!"),
        email_verified=True,
      ),
    )
    await session.commit()

  await client.post(
    "/auth/login",
    json={"email": email, "password": "RefreshPass123!"},
  )
  login_verified = await client.post(
    "/auth/login/verify",
    json={"email": email, "code": sent_emails[-1][1]},
  )
  assert login_verified.status_code == 200
  original_cookie = _refresh_cookie(login_verified)

  refreshed = await client.post(
    "/auth/refresh",
    headers={"Cookie": f"opspilot_refresh={original_cookie}"},
  )
  assert refreshed.status_code == 200
  replacement_cookie = _refresh_cookie(refreshed)
  assert replacement_cookie != original_cookie

  logged_out = await client.post(
    "/auth/logout",
    headers={"Cookie": f"opspilot_refresh={replacement_cookie}"},
  )
  assert logged_out.status_code == 204
  rejected_refresh = await client.post(
    "/auth/refresh",
    headers={"Cookie": f"opspilot_refresh={replacement_cookie}"},
  )
  assert rejected_refresh.status_code == 401


@pytest.mark.asyncio
async def test_email_delivery_failure_is_not_reported_as_success(
  api_client,
  monkeypatch,
):
  client, _session_factory, sent_emails = api_client

  async def reject_email(_recipient: str, _code: str) -> None:
    raise EmailDeliveryError("SMTP rejected recipient")

  monkeypatch.setattr(auth_service, "send_otp_email", reject_email)
  response = await client.post(
    "/auth/register",
    json={
      "email": _email("smtp-failure"),
      "display_name": "SMTP Failure",
      "password": "SmtpPass123!",
    },
  )

  assert response.status_code == 503
  assert sent_emails == []
