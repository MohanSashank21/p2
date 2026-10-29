import hashlib
import hmac
import io
import json
import os
import secrets
import uuid
import zipfile

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db import github, project_membership, user
from app.db.base import Base
from app.db.database import get_db
from app.db.github import (
  GitHubInstallation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.user import User
from app.main import app
from app.services.github_service import _logs_from_archive
from app.utils.jwt import create_access_token


@pytest_asyncio.fixture
async def github_client(tmp_path):
  engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'github.sqlite3'}")

  @event.listens_for(engine.sync_engine, "connect")
  def enable_sqlite_foreign_keys(connection, _connection_record):
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

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

  transport = ASGITransport(app=app, client=(f"github-test-{uuid.uuid4().hex}", 40000))
  async with AsyncClient(transport=transport, base_url="http://testserver") as client:
    yield client, session_factory

  app.dependency_overrides.clear()
  app.dependency_overrides.update(original_overrides)
  await engine.dispose()


async def _create_user(session_factory, label: str) -> User:
  async with session_factory() as session:
    user_record = User(
      email=f"{label}-{secrets.token_hex(8)}@example.com",
      display_name=label,
      password_hash="test-hash",
      email_verified=True,
    )
    session.add(user_record)
    await session.commit()
    return user_record


async def _create_project(client: AsyncClient, owner: User, name: str) -> uuid.UUID:
  response = await client.post(
    "/projects",
    json={"name": name},
    headers={"Authorization": f"Bearer {create_access_token(owner.id)}"},
  )
  assert response.status_code == 201
  return uuid.UUID(response.json()["id"])


@pytest.mark.asyncio
async def test_github_webhook_is_verified_and_deduplicated(github_client):
  client, session_factory = github_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "GitHub project")

  original_secret = settings.GITHUB_WEBHOOK_SECRET
  settings.GITHUB_WEBHOOK_SECRET = SecretStr("test-webhook-secret")
  try:
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
      await session.commit()

    payload = {
      "action": "completed",
      "repository": {"id": 456, "full_name": "example/project"},
      "workflow_run": {"conclusion": "failure"},
    }
    raw = json.dumps(payload).encode("utf-8")
    signature = "sha256=" + hmac.new(
      b"test-webhook-secret",
      raw,
      hashlib.sha256,
    ).hexdigest()

    response = await client.post(
      "/webhooks/github",
      content=raw,
      headers={
        "x-github-event": "workflow_run",
        "x-github-delivery": "delivery-1",
        "x-hub-signature-256": signature,
      },
    )
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] is True
    assert body["duplicate"] is False
    assert body["stored_count"] == 1

    duplicate = await client.post(
      "/webhooks/github",
      content=raw,
      headers={
        "x-github-event": "workflow_run",
        "x-github-delivery": "delivery-1",
        "x-hub-signature-256": signature,
      },
    )
    assert duplicate.status_code == 202
    duplicate_body = duplicate.json()
    assert duplicate_body["accepted"] is True
    assert duplicate_body["duplicate"] is True
    assert duplicate_body["stored_count"] == 0
  finally:
    settings.GITHUB_WEBHOOK_SECRET = original_secret


@pytest.mark.asyncio
async def test_connected_repository_endpoints_return_project_repository(
  github_client,
):
  client, session_factory = github_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "GitHub repository project")

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
      default_branch="main",
      html_url="https://github.com/example/project",
      status="active",
    )
    session.add(repository)
    await session.commit()

  headers = {"Authorization": f"Bearer {create_access_token(owner.id)}"}
  base_url = f"/projects/{project_id}/github/repositories"

  listed = await client.get(base_url, headers=headers)
  assert listed.status_code == 200
  assert len(listed.json()) == 1
  assert listed.json()[0]["id"] == 456
  assert listed.json()[0]["installation_id"] == 12345

  fetched = await client.get(f"{base_url}/456", headers=headers)
  assert fetched.status_code == 200
  assert fetched.json()["id"] == 456
  assert fetched.json()["full_name"] == "example/project"

  events = await client.get(f"{base_url}/456/webhook-events", headers=headers)
  assert events.status_code == 200
  assert events.json() == []


@pytest.mark.asyncio
async def test_central_webhook_stores_only_failed_completed_workflow_runs(
  github_client,
):
  client, session_factory = github_client
  owner = await _create_user(session_factory, "owner")
  project_id = await _create_project(client, owner, "GitHub events project")

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
    await session.commit()

  original_secret = settings.GITHUB_WEBHOOK_SECRET
  settings.GITHUB_WEBHOOK_SECRET = SecretStr("test-webhook-secret")
  try:
    deliveries = (
      ("push", {"repository": {"id": 456}, "commits": []}, False),
      (
        "pull_request",
        {
          "action": "opened",
          "repository": {"id": 456},
          "pull_request": {"number": 17},
        },
        False,
      ),
      (
        "workflow_run",
        {
          "action": "completed",
          "repository": {"id": 456},
          "workflow_run": {"id": 986, "conclusion": "success"},
        },
        False,
      ),
      (
        "workflow_run",
        {
          "action": "in_progress",
          "repository": {"id": 456},
          "workflow_run": {"id": 987, "conclusion": "failure"},
        },
        False,
      ),
      (
        "workflow_run",
        {
          "action": "completed",
          "repository": {"id": 456},
          "workflow_run": {"id": 987, "conclusion": "failure"},
        },
        True,
      ),
      (
        "workflow_run",
        {
          "action": "completed",
          "repository": {"id": 456},
          "workflow_run": {"id": 989, "conclusion": "timed_out"},
        },
        True,
      ),
      (
        "workflow_run",
        {
          "action": "completed",
          "repository": {"id": 456},
          "workflow_run": {"id": 990, "conclusion": "unexpected"},
        },
        True,
      ),
      (
        "workflow_run",
        {
          "action": "completed",
          "repository": {"id": 456},
          "workflow_run": {"id": 988, "conclusion": "cancelled"},
        },
        False,
      ),
    )
    for index, (event_name, payload, should_store) in enumerate(
      deliveries,
      start=1,
    ):
      raw = json.dumps(payload).encode("utf-8")
      signature = "sha256=" + hmac.new(
        b"test-webhook-secret",
        raw,
        hashlib.sha256,
      ).hexdigest()
      response = await client.post(
        "/webhooks/github",
        content=raw,
        headers={
          "x-github-event": event_name,
          "x-github-delivery": f"delivery-{index}",
          "x-hub-signature-256": signature,
        },
      )
      assert response.status_code == 202
      assert response.json()["accepted"] is True
      assert response.json()["stored_count"] == int(should_store)
      if not should_store:
        assert response.json()["ignored_reason"] == (
          "Only completed workflow failures are stored"
        )

    events = await client.get(
      f"/projects/{project_id}/github/repositories/456/webhook-events",
      headers={"Authorization": f"Bearer {create_access_token(owner.id)}"},
    )
    assert events.status_code == 200
    assert len(events.json()) == 3
    assert {event["event_name"] for event in events.json()} == {"workflow_run"}
    assert {
      event["payload"]["workflow_run"]["conclusion"]
      for event in events.json()
    } == {"failure", "timed_out", "unexpected"}
  finally:
    settings.GITHUB_WEBHOOK_SECRET = original_secret


@pytest.mark.asyncio
async def test_failed_workflow_investigation_fetches_github_context(
  github_client,
  monkeypatch,
):
  client, session_factory = github_client
  owner = await _create_user(session_factory, "investigation-owner")
  project_id = await _create_project(client, owner, "GitHub investigation project")

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
      delivery_id="failed-run-delivery",
      event_name="workflow_run",
      action="completed",
      payload={
        "repository": {"id": 456},
        "workflow_run": {
          "id": 987,
          "head_sha": "a" * 40,
          "head_branch": "main",
          "conclusion": "failure",
        },
      },
    )
    session.add(webhook_event)
    await session.commit()
    event_id = webhook_event.id

  async def fake_create_installation_token(installation_id):
    assert installation_id == 12345
    return "installation-token"

  async def fake_get_workflow_run(token, full_name, run_id):
    assert (token, full_name, run_id) == ("installation-token", "example/project", 987)
    return {"id": run_id, "conclusion": "failure"}

  async def fake_get_workflow_jobs(token, full_name, run_id, *, page, per_page):
    assert (run_id, page, per_page) == (987, 1, 100)
    return [{"name": "test", "conclusion": "failure"}]

  async def fake_get_commit(token, full_name, sha):
    assert sha == "a" * 40
    return {
      "sha": sha,
      "commit": {"message": "Fix failing test"},
      "files": [
        {
          "filename": "app.py",
          "patch": "@@ -1 +1 @@\n-bad\n+good",
          "status": "modified",
          "size": 20,
        },
      ],
    }

  async def fake_get_file(token, full_name, path, ref):
    assert (full_name, path, ref) == ("example/project", "app.py", "a" * 40)
    return {"path": path, "content": "print('fixed')", "sha": "file-sha"}

  async def fake_get_commits(token, full_name, *, page, per_page, ref):
    assert (page, per_page, ref) == (1, 10, "a" * 40)
    return [{"sha": ref, "commit": {"message": "Fix failing test"}}]

  async def fake_get_workflow_run_logs(token, full_name, run_id):
    assert run_id == 987
    return {"available": True, "logs": "failing assertion", "truncated": False}

  from app.services import github_project_service

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
    "get_file",
    fake_get_file,
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

  response = await client.get(
    f"/projects/{project_id}/github/repositories/456/"
    f"webhook-events/{event_id}/investigation",
    headers={"Authorization": f"Bearer {create_access_token(owner.id)}"},
  )
  assert response.status_code == 200
  body = response.json()
  assert body["repository"] == "example/project"
  assert body["workflow_run"]["conclusion"] == "failure"
  assert body["jobs"] == [{"name": "test", "conclusion": "failure"}]
  assert body["commit"]["files"][0]["filename"] == "app.py"
  assert body["code_files"] == [
    {"path": "app.py", "content": "print('fixed')", "sha": "file-sha"},
  ]
  assert body["code_files_unavailable"] == []
  assert body["code_files_truncated"] is False
  assert body["commit_history"][0]["commit"]["message"] == "Fix failing test"
  assert body["logs"] == "failing assertion"
  assert body["logs_available"] is True
  assert body["logs_truncated"] is False


def test_workflow_log_archive_is_returned_with_a_size_limit():
  buffer = io.BytesIO()
  with zipfile.ZipFile(buffer, "w") as archive:
    archive.writestr("job/step.txt", "failure details")
  result = _logs_from_archive(buffer.getvalue())
  assert result == {
    "available": True,
    "logs": "===== job/step.txt =====\nfailure details",
    "truncated": False,
  }

  large_buffer = io.BytesIO()
  with zipfile.ZipFile(large_buffer, "w") as archive:
    archive.writestr("job/large.txt", "x" * 300_000)
  large_result = _logs_from_archive(large_buffer.getvalue())
  assert large_result["available"] is True
  assert large_result["truncated"] is True
  assert len(large_result["logs"]) < 251_000
