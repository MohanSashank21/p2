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
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import auth, environment, membership, organisation, project, user
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


@pytest_asyncio.fixture
async def api_client(tmp_path, monkeypatch):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'auth-resend.sqlite3'}",
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
