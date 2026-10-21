import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
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
from app.main import app


@pytest_asyncio.fixture
async def client(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'retired-organisations.sqlite3'}",
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

  async def override_database():
    async with session_factory() as session:
      yield session

  original_overrides = app.dependency_overrides.copy()
  app.dependency_overrides[get_db] = override_database
  transport = ASGITransport(app=app)
  async with AsyncClient(
    transport=transport,
    base_url="http://testserver",
  ) as api_client:
    yield api_client

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await engine.dispose()


@pytest.mark.asyncio
async def test_organization_routes_are_no_longer_active(client):
  response = await client.get("/organisations")
  invitation_acceptance = await client.post(
    "/organisations/invitations/accept",
    json={"token": "a" * 32},
  )

  assert response.status_code == 404
  assert invitation_acceptance.status_code == 404
