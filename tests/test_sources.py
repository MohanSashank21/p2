import asyncio
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("JWT_ACCESS_SECRET_KEY", "test-access-secret-not-for-production-000001")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-not-for-production-000002")
os.environ.setdefault("OTP_HASH_SECRET_KEY", "test-otp-hmac-secret-not-for-production-000003")

import pytest
import pytest_asyncio
import httpx
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import event, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import docker as docker_api
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
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import AlertmanagerAlert, IncidentSource, SourceEvent
from app.db.github import (
  GitHubInstallation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.core.config import settings
from app.services import incident_investigation_service, loki_service, trace_service
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
  test_database_url = os.getenv("OPSPILOT_TEST_DATABASE_URL")
  schema_name = f"test_{uuid.uuid4().hex}"
  if test_database_url:
    engine = create_async_engine(
      test_database_url,
      execution_options={"schema_translate_map": {None: schema_name}},
    )
  else:
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
    if test_database_url:
      await connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
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
  if test_database_url:
    async with engine.begin() as connection:
      await connection.execute(text(f'DROP SCHEMA "{schema_name}" CASCADE'))
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
  source_type: str = "generic_webhook",
):
  return await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": name,
      "source_type": source_type,
      "environment_id": str(environment_id) if environment_id else None,
      **({"loki_url": "https://loki.test"} if source_type == "loki" else {}),
    },
    headers=_headers(owner),
  )


def _alertmanager_payload(
  *alerts: dict,
  group_key: str = "test-group",
) -> dict:
  return {
    "receiver": "opspilot",
    "status": "firing",
    "version": "4",
    "groupKey": group_key,
    "groupLabels": {},
    "commonLabels": {},
    "commonAnnotations": {},
    "externalURL": "http://alertmanager.test",
    "alerts": list(alerts),
  }


def _alertmanager_alert(
  fingerprint: str,
  *,
  status: str = "firing",
  name: str = "HighCPU",
  severity: str = "critical",
  starts_at: str = "2026-10-22T08:00:00Z",
  ends_at: str = "0001-01-01T00:00:00Z",
  summary: str = "CPU usage is high",
  labels: dict[str, str] | None = None,
) -> dict:
  return {
    "status": status,
    "labels": {
      "alertname": name,
      "severity": severity,
      "instance": "server-01",
      **(labels or {}),
    },
    "annotations": {
      "summary": summary,
      "description": "Production CPU is above threshold",
    },
    "startsAt": starts_at,
    "endsAt": ends_at,
    "generatorURL": "http://prometheus.test/graph",
    "fingerprint": fingerprint,
  }


def _grafana_alert(
  fingerprint: str,
  *,
  status: str = "firing",
  ends_at: str = "0001-01-01T00:00:00Z",
) -> dict:
  return {
    "status": status,
    "labels": {
      "alertname": "HighCPU",
      "severity": "critical",
      "instance": "server-01",
    },
    "annotations": {
      "summary": "CPU usage exceeded 90%",
      "description": "Production CPU is above threshold.",
    },
    "startsAt": "2026-10-22T08:00:00Z",
    "endsAt": ends_at,
    "generatorURL": "https://grafana.example/alerting/rule",
    "fingerprint": fingerprint,
    "dashboardURL": "https://grafana.example/d/abc",
    "panelURL": "https://grafana.example/d/abc?viewPanel=1",
    "silenceURL": "https://grafana.example/alerting/silence/new",
    "imageURL": "https://grafana.example/render/panel.png",
    "values": {"A": 95.2},
  }


def _grafana_payload(alert: dict) -> dict:
  return {
    "receiver": "OpsPilot",
    "status": alert["status"],
    "orgId": 1,
    "version": "1",
    "groupKey": '{}:{alertname="HighCPU"}',
    "groupLabels": {"alertname": "HighCPU"},
    "commonLabels": {"severity": "critical"},
    "commonAnnotations": {"summary": "CPU usage exceeded 90%"},
    "externalURL": "https://grafana.example/",
    "alerts": [alert],
  }


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


def test_alertmanager_openapi_documents_provider_payload_and_source_auth():
  operation = app.openapi()["paths"][
    "/webhooks/sources/{source_id}/alertmanager"
  ]["post"]
  body_schema = operation["requestBody"]["content"]["application/json"]["schema"]

  assert operation["security"] == [{"SourceCredential": []}]
  assert body_schema["required"] == ["alerts"]
  alert_schema = body_schema["properties"]["alerts"]["items"]
  assert {"startsAt", "fingerprint"} <= set(alert_schema["required"])
  assert {"labels", "annotations"} <= set(alert_schema["properties"])
  assert operation["requestBody"]["content"]["application/json"]["example"][
    "alerts"
  ][0]["fingerprint"] == "a1b2c3d4"


def test_grafana_openapi_documents_default_webhook_and_source_auth():
  operation = app.openapi()["paths"][
    "/webhooks/sources/{source_id}/grafana"
  ]["post"]
  body_schema = operation["requestBody"]["content"]["application/json"]["schema"]
  alert_schema = body_schema["properties"]["alerts"]["items"]

  assert operation["security"] == [{"SourceCredential": []}]
  assert {"type": "integer"} in body_schema["properties"]["orgId"]["anyOf"]
  assert {
    "startsAt",
    "fingerprint",
    "dashboardURL",
    "panelURL",
    "values",
  } <= set(alert_schema["properties"])
  assert operation["requestBody"]["content"]["application/json"]["example"][
    "alerts"
  ][0]["fingerprint"] == "a1b2c3d4"


@pytest.mark.asyncio
async def test_grafana_webhook_lifecycle_is_idempotent_and_preserves_metadata(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "grafana-owner")
  project_id = await _create_project(client, owner, "Grafana project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="grafana",
  )
  source_body = source.json()
  url = f"/webhooks/sources/{source_body['id']}/grafana"
  headers = {"Authorization": f"Bearer {source_body['credential']}"}

  firing = _grafana_payload(_grafana_alert("grafana-fingerprint"))
  firing["alerts"].append(
    _grafana_alert("second-grafana-fingerprint"),
  )
  created = await client.post(url, json=firing, headers=headers)
  repeated = await client.post(url, json=firing, headers=headers)
  incident_id = created.json()["alerts"][0]["incident_id"]
  second_incident_id = created.json()["alerts"][1]["incident_id"]
  resolved_payload = _grafana_payload(
    _grafana_alert(
      "grafana-fingerprint",
      status="resolved",
      ends_at="2026-10-22T08:30:00Z",
    ),
  )
  resolved = await client.post(url, json=resolved_payload, headers=headers)
  unmatched = await client.post(
    url,
    json=_grafana_payload(
      _grafana_alert(
        "unmatched-grafana-fingerprint",
        status="resolved",
        ends_at="2026-10-22T08:30:00Z",
      ),
    ),
    headers=headers,
  )

  assert created.status_code == repeated.status_code == 200
  assert created.json()["created"] == 2
  assert repeated.json()["updated"] == 2
  assert incident_id != second_incident_id
  assert repeated.json()["alerts"][0]["incident_id"] == incident_id
  assert resolved.json()["resolved"] == 1
  assert resolved.json()["alerts"][0]["incident_id"] == incident_id
  assert unmatched.json()["ignored"] == 1

  async with session_factory() as session:
    alerts = list(await session.scalars(select(AlertmanagerAlert)))
    incidents = list(
      await session.scalars(
        select(Incident).where(Incident.source_type == "grafana"),
      ),
    )
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "grafana_notification",
        ),
      ),
    )
  assert len(alerts) == 2
  assert len(incidents) == 2
  assert {incident.id: incident.status for incident in incidents} == {
    uuid.UUID(incident_id): "resolved",
    uuid.UUID(second_incident_id): "open",
  }
  assert len(evidence) == 3
  assert any(
    item.original_content["alert"]["dashboardURL"]
    == "https://grafana.example/d/abc"
    and item.normalized_content["provider_metadata"]["panelURL"]
    == "https://grafana.example/d/abc?viewPanel=1"
    for item in evidence
  )


@pytest.mark.asyncio
async def test_grafana_firing_automatically_retrieves_matching_loki_logs(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "LOKI_ALLOWED_HOSTS", "loki.test")
  owner = await _create_user(session_factory, "automatic-loki-owner")
  project_id = await _create_project(client, owner, "Automatic Loki project")
  grafana_source = await _create_source(
    client,
    project_id,
    owner,
    name="Automatic Grafana",
    source_type="grafana",
  )
  loki_source = await _create_source(
    client,
    project_id,
    owner,
    name="Automatic Loki",
    source_type="loki",
  )
  configured = await client.patch(
    f"/projects/{project_id}/sources/{loki_source.json()['id']}/loki",
    json={
      "loki_url": "https://loki.test",
      "loki_auth_type": "none",
    },
    headers=_headers(owner),
  )
  assert configured.status_code == 200

  requests = []
  real_async_client = httpx.AsyncClient

  def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    if request.url.path.endswith("/loki/api/v1/labels"):
      return httpx.Response(
        200,
        json={
          "status": "success",
          "data": ["environment", "job", "service_name", "detected_level"],
        },
      )
    if request.url.path.endswith("/loki/api/v1/label/job/values"):
      return httpx.Response(
        200,
        json={"status": "success", "data": ["prometheus", "opspilot-test"]},
      )
    if request.url.path.endswith("/loki/api/v1/label/service_name/values"):
      return httpx.Response(
        200,
        json={"status": "success", "data": ["demo-app"]},
      )
    if request.url.path.endswith("/loki/api/v1/label/environment/values"):
      return httpx.Response(
        200,
        json={"status": "success", "data": ["local"]},
      )
    if request.url.path.endswith("/loki/api/v1/query_range"):
      return httpx.Response(
        200,
        json={
          "status": "success",
          "data": {
            "resultType": "streams",
            "result": [
              {
                "stream": {
                  "job": "opspilot-test",
                  "service_name": "demo-app",
                  "environment": "local",
                },
                "values": [
                  [str(int(datetime.now(UTC).timestamp() * 1_000_000_000)),
                   "ERROR test log"],
                ],
              },
            ],
          },
        },
      )
    raise AssertionError(f"Unexpected Loki API request: {request.url}")

  def mock_async_client(*args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(handler)
    return real_async_client(*args, **kwargs)

  monkeypatch.setattr(loki_service.httpx, "AsyncClient", mock_async_client)
  started_at = datetime.now(UTC) - timedelta(seconds=30)
  alert = _grafana_alert("automatic-loki-fingerprint")
  alert["startsAt"] = started_at.isoformat()
  alert["labels"].update(
    {
      "job": "opspilot-test",
      "service_name": "demo-app",
      "environment": "local",
      "app": "prometheus",
    },
  )
  payload = _grafana_payload(alert)
  webhook_url = f"/webhooks/sources/{grafana_source.json()['id']}/grafana"
  headers = {"Authorization": f"Bearer {grafana_source.json()['credential']}"}

  response = await client.post(webhook_url, json=payload, headers=headers)
  incident_id = response.json()["alerts"][0]["incident_id"]
  repeated = await client.post(webhook_url, json=payload, headers=headers)

  assert response.status_code == repeated.status_code == 200
  automatic_result = response.json()["alerts"][0]["loki_retrieval"][0]
  assert automatic_result["status"] == "success"
  assert automatic_result["entry_count"] == 1
  assert repeated.json()["alerts"][0]["loki_retrieval"][0]["status"] == (
    "already_retrieved"
  )
  query_requests = [
    request
    for request in requests
    if request.url.path.endswith("/loki/api/v1/query_range")
  ]
  assert len(query_requests) == 1
  assert query_requests[0].url.params["query"] == (
    '{environment="local",job="opspilot-test",service_name="demo-app"}'
  )
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.incident_id == uuid.UUID(incident_id),
          IncidentEvidence.evidence_type == "loki_logs",
        ),
      ),
    )
  assert len(evidence) == 1
  assert evidence[0].original_content["entries"][0]["line"] == "ERROR test log"
  assert evidence[0].original_content["selector_labels"] == {
    "environment": "local",
    "job": "opspilot-test",
    "service_name": "demo-app",
  }


async def _create_labeled_test_incident(
  session_factory: async_sessionmaker[AsyncSession],
  project_id: uuid.UUID,
) -> Incident:
  async with session_factory() as session:
    incident = Incident(
      project_id=project_id,
      source_type="grafana",
      incident_type="monitoring_alert",
      title="Loki evidence test",
      severity="high",
      status="open",
    )
    session.add(incident)
    await session.flush()
    session.add(
      IncidentEvidence(
        incident_id=incident.id,
        evidence_type="grafana_notification",
        original_content={},
        normalized_content={
          "labels": {"service": "api", "environment": "test"},
        },
      ),
    )
    await session.commit()
    await session.refresh(incident)
    return incident


@pytest.mark.asyncio
async def test_loki_source_configuration_encrypts_credentials_and_is_owner_only(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "LOKI_ALLOWED_HOSTS", "loki.test")
  encryption_key = Fernet.generate_key().decode("ascii")
  monkeypatch.setattr(
    settings,
    "LOKI_CREDENTIAL_ENCRYPTION_KEY",
    SecretStr(encryption_key),
  )
  owner = await _create_user(session_factory, "loki-owner")
  member = await _create_user(session_factory, "loki-member")
  project_id = await _create_project(client, owner, "Loki project")
  await _create_member(session_factory, project_id, member)

  created = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Loki",
      "source_type": "loki",
      "loki_url": "https://loki.test",
      "loki_tenant_id": "tenant-a",
      "loki_auth_type": "bearer",
      "loki_bearer_token": "do-not-return-this-token",
    },
    headers=_headers(owner),
  )
  source_id = created.json()["id"]
  updated = await client.patch(
    f"/projects/{project_id}/sources/{source_id}/loki",
    json={
      "loki_url": "https://loki.test",
      "loki_tenant_id": "tenant-b",
      "loki_auth_type": "basic",
      "loki_username": "loki-user",
      "loki_password": "do-not-return-this-password",
      "enabled": True,
    },
    headers=_headers(owner),
  )
  denied = await client.patch(
    f"/projects/{project_id}/sources/{source_id}/loki",
    json={
      "loki_url": "https://loki.test",
      "loki_auth_type": "none",
    },
    headers=_headers(member),
  )
  listed = await client.get(
    f"/projects/{project_id}/sources",
    headers=_headers(owner),
  )

  assert created.status_code == 201
  assert updated.status_code == 200
  assert denied.status_code == 403
  assert updated.json()["loki_tenant_id"] == "tenant-b"
  assert updated.json()["loki_auth_configured"] is True
  assert "do-not-return-this-password" not in updated.text
  assert "do-not-return-this-token" not in listed.text
  async with session_factory() as session:
    source = await session.get(IncidentSource, uuid.UUID(source_id))
    assert source is not None
    assert source.loki_auth_ciphertext != "do-not-return-this-password"
    assert source.loki_auth_ciphertext != "do-not-return-this-token"
    auth = loki_service._request_auth(
      loki_service.LokiConnection(
        base_url=source.loki_url,
        tenant_id=source.loki_tenant_id,
        auth_type=source.loki_auth_type,
        auth_ciphertext=source.loki_auth_ciphertext,
      ),
    )
  assert isinstance(auth, httpx.BasicAuth)


@pytest.mark.asyncio
async def test_loki_rejects_non_allowlisted_hosts_and_invalid_auth_settings(
  source_client,
  monkeypatch,
):
  client, _session_factory, _redis = source_client
  monkeypatch.setattr(settings, "LOKI_ALLOWED_HOSTS", "loki.test")
  owner = await _create_user(_session_factory, "loki-validation-owner")
  project_id = await _create_project(client, owner, "Loki validation")

  disallowed = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Wrong host",
      "source_type": "loki",
      "loki_url": "http://127.0.0.1:3100",
    },
    headers=_headers(owner),
  )
  invalid_auth = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Missing token",
      "source_type": "loki",
      "loki_url": "https://loki.test",
      "loki_auth_type": "bearer",
    },
    headers=_headers(owner),
  )

  assert disallowed.status_code == 422
  assert invalid_auth.status_code == 422


@pytest.mark.asyncio
async def test_loki_query_persists_bounded_results_and_deduplicates_evidence(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "LOKI_ALLOWED_HOSTS", "loki.test")
  owner = await _create_user(session_factory, "loki-query-owner")
  outsider = await _create_user(session_factory, "loki-query-outsider")
  project_id = await _create_project(client, owner, "Loki query project")
  source = await _create_source(
    client,
    project_id,
    owner,
    name="Loki query source",
    source_type="loki",
  )
  source_id = source.json()["id"]
  configured = await client.patch(
    f"/projects/{project_id}/sources/{source_id}/loki",
    json={
      "loki_url": "https://loki.test",
      "loki_tenant_id": "tenant-a",
      "loki_auth_type": "none",
    },
    headers=_headers(owner),
  )
  incident = await _create_labeled_test_incident(session_factory, project_id)
  calls = []
  real_async_client = httpx.AsyncClient

  def handler(request: httpx.Request) -> httpx.Response:
    calls.append(request)
    return httpx.Response(
      200,
      json={
        "status": "success",
        "data": {
          "resultType": "streams",
          "result": [
            {
              "stream": {"service": "api"},
              "values": [["1792663200000000000", "request failed"]],
            },
          ],
        },
      },
    )

  def mock_async_client(*args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(handler)
    return real_async_client(*args, **kwargs)

  monkeypatch.setattr(loki_service.httpx, "AsyncClient", mock_async_client)
  body = {
    "source_id": source_id,
    "start": "2026-10-22T08:00:00Z",
    "end": "2026-10-22T08:05:00Z",
    "labels": {"service": "api"},
    "limit": 25,
  }
  url = f"/projects/{project_id}/incidents/{incident.id}/loki-logs"
  first = await client.post(url, json=body, headers=_headers(owner))
  repeated = await client.post(url, json=body, headers=_headers(owner))
  mismatched_selector = await client.post(
    url,
    json={**body, "labels": {"service": "other"}},
    headers=_headers(owner),
  )
  unauthorized = await client.post(
    url,
    json=body,
    headers=_headers(outsider),
  )

  assert configured.status_code == 200
  assert first.status_code == repeated.status_code == 200
  assert mismatched_selector.status_code == 422
  assert unauthorized.status_code == 404
  assert first.json()["status"] == "success"
  assert first.json()["entry_count"] == 1
  assert repeated.json()["evidence"]["id"] == first.json()["evidence"]["id"]
  assert len(calls) == 2
  assert calls[0].url.params["query"] == '{service="api"}'
  assert calls[0].headers["X-Scope-OrgID"] == "tenant-a"
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "loki_logs",
        ),
      ),
    )
  assert len(evidence) == 1
  assert evidence[0].incident_source_id == uuid.UUID(source_id)
  assert evidence[0].original_content["entries"][0]["line"] == "request failed"


@pytest.mark.asyncio
async def test_loki_empty_result_and_timeout_are_distinguished(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "LOKI_ALLOWED_HOSTS", "loki.test")
  owner = await _create_user(session_factory, "loki-error-owner")
  project_id = await _create_project(client, owner, "Loki error project")
  source = await _create_source(
    client,
    project_id,
    owner,
    name="Loki error source",
    source_type="loki",
  )
  source_id = source.json()["id"]
  await client.patch(
    f"/projects/{project_id}/sources/{source_id}/loki",
    json={"loki_url": "https://loki.test", "loki_auth_type": "none"},
    headers=_headers(owner),
  )
  incident = await _create_labeled_test_incident(session_factory, project_id)
  real_async_client = httpx.AsyncClient
  empty_client = lambda *args, **kwargs: real_async_client(
    transport=httpx.MockTransport(
      lambda _request: httpx.Response(
        200,
        json={"status": "success", "data": {"resultType": "streams", "result": []}},
      ),
    ),
    *args,
    **kwargs,
  )
  monkeypatch.setattr(loki_service.httpx, "AsyncClient", empty_client)
  request_body = {
    "source_id": source_id,
    "start": "2026-10-22T08:00:00Z",
    "end": "2026-10-22T08:05:00Z",
    "labels": {"service": "api"},
  }
  url = f"/projects/{project_id}/incidents/{incident.id}/loki-logs"
  empty = await client.post(url, json=request_body, headers=_headers(owner))
  assert empty.status_code == 200
  assert empty.json()["status"] == "empty"
  assert empty.json()["entry_count"] == 0

  encryption_key = Fernet.generate_key().decode("ascii")
  monkeypatch.setattr(
    settings,
    "LOKI_CREDENTIAL_ENCRYPTION_KEY",
    SecretStr(encryption_key),
  )
  await client.patch(
    f"/projects/{project_id}/sources/{source_id}/loki",
    json={
      "loki_url": "https://loki.test",
      "loki_auth_type": "bearer",
      "loki_bearer_token": "never-return-or-log-this",
    },
    headers=_headers(owner),
  )
  authenticated_requests = []
  unauthorized_client = lambda *args, **kwargs: real_async_client(
    transport=httpx.MockTransport(
      lambda request: (
        authenticated_requests.append(request)
        or httpx.Response(401, text="configured token rejected")
      ),
    ),
    *args,
    **kwargs,
  )
  monkeypatch.setattr(
    loki_service.httpx,
    "AsyncClient",
    unauthorized_client,
  )
  upstream_auth_failure = await client.post(
    url,
    json=request_body,
    headers=_headers(owner),
  )
  assert upstream_auth_failure.status_code == 502
  assert "never-return-or-log-this" not in upstream_auth_failure.text
  assert authenticated_requests[0].headers["Authorization"] == (
    "Bearer never-return-or-log-this"
  )

  def raise_timeout(*args, **kwargs):
    raise httpx.ReadTimeout("timeout")

  monkeypatch.setattr(loki_service.httpx, "AsyncClient", raise_timeout)
  timed_out = await client.post(url, json=request_body, headers=_headers(owner))
  assert timed_out.status_code == 504
  assert "timeout" not in timed_out.text.lower()
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "loki_logs",
        ),
      ),
    )
  assert len(evidence) == 1


@pytest.mark.asyncio
async def test_tempo_source_configuration_is_encrypted_and_owner_only(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "TRACE_ALLOWED_HOSTS", "tempo.test")
  encryption_key = Fernet.generate_key().decode("ascii")
  monkeypatch.setattr(
    settings,
    "TRACE_CREDENTIAL_ENCRYPTION_KEY",
    SecretStr(encryption_key),
  )
  owner = await _create_user(session_factory, "tempo-source-owner")
  member = await _create_user(session_factory, "tempo-source-member")
  project_id = await _create_project(client, owner, "Tempo source project")
  await _create_member(session_factory, project_id, member)

  invalid_host = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Untrusted Tempo",
      "source_type": "traces",
      "trace_backend": "tempo",
      "trace_url": "http://127.0.0.1:3200",
    },
    headers=_headers(owner),
  )
  created = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Production Tempo",
      "source_type": "traces",
      "trace_backend": "tempo",
      "trace_url": "https://tempo.test",
      "trace_service_name": "checkout-api",
      "trace_auth_type": "bearer",
      "trace_bearer_token": "do-not-return-this-token",
      "trace_resource_attributes": {"deployment.environment.name": "production"},
    },
    headers=_headers(owner),
  )
  source_id = created.json()["id"]
  real_async_client = httpx.AsyncClient
  health_requests: list[httpx.Request] = []

  def health_handler(request: httpx.Request) -> httpx.Response:
    health_requests.append(request)
    return httpx.Response(200, json={"version": "2.8.0"})

  monkeypatch.setattr(
    trace_service.httpx,
    "AsyncClient",
    lambda *args, **kwargs: real_async_client(
      transport=httpx.MockTransport(health_handler),
      *args,
      **kwargs,
    ),
  )
  validated = await client.post(
    f"/projects/{project_id}/sources/{source_id}/traces/validate",
    headers=_headers(owner),
  )
  assert validated.status_code == 200
  assert validated.json()["trace_connection_status"] == "connected"
  assert health_requests[0].headers["Authorization"] == (
    "Bearer do-not-return-this-token"
  )

  monkeypatch.setattr(
    trace_service.httpx,
    "AsyncClient",
    lambda *args, **kwargs: real_async_client(
      transport=httpx.MockTransport(
        lambda _request: httpx.Response(401, text="credential rejected"),
      ),
      *args,
      **kwargs,
    ),
  )
  failed_validation = await client.post(
    f"/projects/{project_id}/sources/{source_id}/traces/validate",
    headers=_headers(owner),
  )
  listed = await client.get(
    f"/projects/{project_id}/sources",
    headers=_headers(owner),
  )
  forbidden_update = await client.patch(
    f"/projects/{project_id}/sources/{source_id}/traces",
    json={
      "trace_url": "https://tempo.test",
      "trace_auth_type": "none",
    },
    headers=_headers(member),
  )

  assert invalid_host.status_code == 422
  assert created.status_code == 201
  assert created.json()["trace_backend"] == "tempo"
  assert created.json()["trace_auth_configured"] is True
  assert created.json()["trace_connection_status"] == "not_checked"
  assert "do-not-return-this-token" not in created.text
  assert failed_validation.status_code == 502
  assert "credential rejected" not in failed_validation.text
  assert listed.json()[0]["trace_connection_status"] == "unavailable"
  assert forbidden_update.status_code == 403
  async with session_factory() as session:
    source = await session.get(IncidentSource, uuid.UUID(source_id))
  assert source is not None
  assert source.trace_auth_ciphertext is not None
  decrypted = json.loads(
    Fernet(encryption_key.encode("ascii")).decrypt(
      source.trace_auth_ciphertext.encode("ascii"),
    ),
  )
  assert decrypted == {"token": "do-not-return-this-token"}


@pytest.mark.asyncio
async def test_tempo_query_normalizes_and_deduplicates_incident_evidence(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "TRACE_ALLOWED_HOSTS", "tempo.test")
  owner = await _create_user(session_factory, "tempo-query-owner")
  project_id = await _create_project(client, owner, "Tempo query project")
  source = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Tempo",
      "source_type": "traces",
      "trace_backend": "tempo",
      "trace_url": "https://tempo.test",
      "trace_service_name": "checkout-api",
    },
    headers=_headers(owner),
  )
  assert source.status_code == 201
  source_id = source.json()["id"]
  incident = await _create_labeled_test_incident(session_factory, project_id)
  trace_id = "a" * 32
  calls: list[httpx.Request] = []
  return_empty = False

  def handler(request: httpx.Request) -> httpx.Response:
    nonlocal return_empty
    calls.append(request)
    if request.url.path.endswith("/api/search"):
      if return_empty:
        return httpx.Response(200, json={"traces": []})
      return httpx.Response(
        200,
        json={
          "traces": [
            {
              "traceID": trace_id,
              "startTimeUnixNano": "1000000000",
              "durationMs": 1.0,
              "rootServiceName": "checkout-api",
              "rootTraceName": "GET /checkout",
            },
          ],
        },
      )
    if request.url.path.endswith(f"/api/traces/{trace_id}"):
      return httpx.Response(
        200,
        json={
          "batches": [
            {
              "resource": {
                "attributes": [
                  {
                    "key": "service.name",
                    "value": {"stringValue": "checkout-api"},
                  },
                ],
              },
              "instrumentationLibrarySpans": [
                {
                  "spans": [
                    {
                      "traceId": trace_id,
                      "spanId": "b" * 16,
                      "parentSpanId": "c" * 16,
                      "name": "GET /checkout",
                      "startTimeUnixNano": "1000000000",
                      "endTimeUnixNano": "2000000000",
                      "status": {"code": 2, "message": "database timeout"},
                      "attributes": [
                        {
                          "key": "http.response.status_code",
                          "value": {"intValue": "503"},
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      )
    return httpx.Response(404)

  real_async_client = httpx.AsyncClient

  def mock_async_client(*args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(handler)
    return real_async_client(*args, **kwargs)

  monkeypatch.setattr(trace_service.httpx, "AsyncClient", mock_async_client)
  end = datetime.now(UTC)
  start = end - timedelta(minutes=5)
  body = {
    "source_id": source_id,
    "start": start.isoformat(),
    "end": end.isoformat(),
    "span_status": "error",
    "limit": 5,
  }
  url = f"/projects/{project_id}/incidents/{incident.id}/traces"
  first = await client.post(url, json=body, headers=_headers(owner))
  repeated = await client.post(url, json=body, headers=_headers(owner))

  assert first.status_code == repeated.status_code == 200
  assert first.json()["status"] == "success"
  assert first.json()["trace_count"] == 1
  assert first.json()["span_count"] == 1
  assert first.json()["evidence"]["id"] == repeated.json()["evidence"]["id"]
  trace_evidence = first.json()["evidence"]["original_content"]["traces"][0]
  span = trace_evidence["spans"][0]
  assert trace_evidence["trace_id"] == trace_id
  assert span["service_name"] == "checkout-api"
  assert span["parent_span_id"] == "c" * 16
  assert span["duration_ms"] == 1000
  assert span["status"] == "error"
  assert span["status_message"] == "database timeout"
  assert span["attributes"]["http.response.status_code"] == 503
  assert len(calls) == 4
  assert calls[0].url.params["q"] == (
    '{ status=error && resource.service.name="checkout-api" }'
  )
  assert calls[1].url.path == f"/api/traces/{trace_id}"

  return_empty = True
  empty_start = start - timedelta(minutes=1)
  empty = await client.post(
    url,
    json={
      **body,
      "start": empty_start.isoformat(),
      "end": (end - timedelta(minutes=1)).isoformat(),
    },
    headers=_headers(owner),
  )
  assert empty.status_code == 200
  assert empty.json()["status"] == "empty"
  assert empty.json()["trace_count"] == 0

  by_trace_id = await client.post(
    url,
    json={**body, "trace_id": trace_id, "span_status": None},
    headers=_headers(owner),
  )
  assert by_trace_id.status_code == 200
  assert by_trace_id.json()["status"] == "success"
  assert calls[-1].url.path == f"/api/traces/{trace_id}"

  unbounded = await client.post(
    url,
    json={
      **body,
      "trace_id": None,
      "service_name": None,
      "start": (end - timedelta(hours=8)).isoformat(),
    },
    headers=_headers(owner),
  )
  assert unbounded.status_code == 422
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "trace_spans",
        ),
      ),
    )
    persisted_incident = await session.get(Incident, incident.id)
  assert len(evidence) == 3
  assert persisted_incident is not None
  assert persisted_incident.status == "open"


@pytest.mark.asyncio
async def test_tempo_auth_failure_and_timeout_do_not_create_incidents_or_evidence(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  monkeypatch.setattr(settings, "TRACE_ALLOWED_HOSTS", "tempo.test")
  owner = await _create_user(session_factory, "tempo-failure-owner")
  project_id = await _create_project(client, owner, "Tempo failure project")
  source = await client.post(
    f"/projects/{project_id}/sources",
    json={
      "name": "Unavailable Tempo",
      "source_type": "traces",
      "trace_backend": "tempo",
      "trace_url": "https://tempo.test",
      "trace_service_name": "checkout-api",
    },
    headers=_headers(owner),
  )
  incident = await _create_labeled_test_incident(session_factory, project_id)
  end = datetime.now(UTC)
  body = {
    "source_id": source.json()["id"],
    "start": (end - timedelta(minutes=5)).isoformat(),
    "end": end.isoformat(),
  }
  real_async_client = httpx.AsyncClient

  def mock_async_client(status_code: int):
    return lambda *args, **kwargs: real_async_client(
      transport=httpx.MockTransport(
        lambda _request: httpx.Response(status_code, text="backend failure"),
      ),
      *args,
      **kwargs,
    )

  monkeypatch.setattr(
    trace_service.httpx,
    "AsyncClient",
    mock_async_client(401),
  )
  url = f"/projects/{project_id}/incidents/{incident.id}/traces"
  unauthorized = await client.post(url, json=body, headers=_headers(owner))

  def raise_timeout(*args, **kwargs):
    raise httpx.ReadTimeout("timeout")

  monkeypatch.setattr(trace_service.httpx, "AsyncClient", raise_timeout)
  timed_out = await client.post(url, json=body, headers=_headers(owner))

  assert unauthorized.status_code == 502
  assert "backend failure" not in unauthorized.text
  assert timed_out.status_code == 504
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "trace_spans",
        ),
      ),
    )
    persisted_incident = await session.get(Incident, incident.id)
  assert evidence == []
  assert persisted_incident is not None
  assert persisted_incident.status == "open"


@pytest.mark.asyncio
async def test_alertmanager_batch_creates_incidents_and_retries_are_idempotent(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "alertmanager-owner")
  project_id = await _create_project(client, owner, "Alertmanager project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  url = f"/webhooks/sources/{source.json()['id']}/alertmanager"
  headers = {"Authorization": f"Bearer {source.json()['credential']}"}
  body = _alertmanager_payload(
    _alertmanager_alert("fingerprint-1"),
    _alertmanager_alert(
      "fingerprint-2",
      name="HighMemory",
      severity="warning",
      summary="Memory usage is high",
    ),
  )

  first = await client.post(url, json=body, headers=headers)
  retry = await client.post(url, json=body, headers=headers)

  assert first.status_code == retry.status_code == 200
  assert first.json()["received"] == 2
  assert first.json()["created"] == 2
  assert [item["outcome"] for item in retry.json()["alerts"]] == [
    "updated",
    "updated",
  ]
  assert [
    item["incident_id"] for item in retry.json()["alerts"]
  ] == [item["incident_id"] for item in first.json()["alerts"]]

  async with session_factory() as session:
    alerts = list(await session.scalars(select(AlertmanagerAlert)))
    incidents = list(
      await session.scalars(
        select(Incident).where(Incident.source_type == "alertmanager"),
      ),
    )
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "alertmanager_notification",
        ),
      ),
    )
  assert len(alerts) == 2
  assert len(incidents) == 2
  assert len(evidence) == 2
  assert {alert.project_id for alert in alerts} == {project_id}


@pytest.mark.asyncio
async def test_alertmanager_repeat_updates_latest_details_without_new_incident(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "repeat-owner")
  project_id = await _create_project(client, owner, "Repeat project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  url = f"/webhooks/sources/{source.json()['id']}/alertmanager"
  headers = {"Authorization": f"Bearer {source.json()['credential']}"}

  created = await client.post(
    url,
    json=_alertmanager_payload(_alertmanager_alert("stable-fingerprint")),
    headers=headers,
  )
  repeated = await client.post(
    url,
    json=_alertmanager_payload(
      _alertmanager_alert(
        "stable-fingerprint",
        severity="warning",
        summary="Updated CPU summary",
        labels={"team": "platform"},
      ),
      group_key="updated-group",
    ),
    headers=headers,
  )

  assert created.json()["created"] == 1
  assert repeated.json()["updated"] == 1
  assert repeated.json()["alerts"][0]["incident_id"] == (
    created.json()["alerts"][0]["incident_id"]
  )
  async with session_factory() as session:
    alert = await session.scalar(select(AlertmanagerAlert))
    incidents = list(
      await session.scalars(
        select(Incident).where(Incident.source_type == "alertmanager"),
      ),
    )
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "alertmanager_notification",
        ),
      ),
    )
  assert alert is not None
  assert alert.severity == "medium"
  assert alert.annotations["summary"] == "Updated CPU summary"
  assert alert.starts_at.isoformat().startswith("2026-10-22T08:00:00")
  assert len(incidents) == 1
  assert incidents[0].severity == "medium"
  assert incidents[0].description == "Production CPU is above threshold"
  assert len(evidence) == 2


@pytest.mark.asyncio
async def test_alertmanager_same_fingerprint_is_scoped_to_each_source(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "source-scope-owner")
  project_id = await _create_project(client, owner, "Source scope")
  sources = [
    await _create_source(
      client,
      project_id,
      owner,
      name=f"Alertmanager {index}",
      source_type="alertmanager",
    )
    for index in range(2)
  ]
  results = []
  for source in sources:
    response = await client.post(
      f"/webhooks/sources/{source.json()['id']}/alertmanager",
      json=_alertmanager_payload(_alertmanager_alert("same-fingerprint")),
      headers={"Authorization": f"Bearer {source.json()['credential']}"},
    )
    results.append(response)

  assert all(response.status_code == 200 for response in results)
  incident_ids = {
    response.json()["alerts"][0]["incident_id"] for response in results
  }
  assert len(incident_ids) == 2
  async with session_factory() as session:
    alerts = list(await session.scalars(select(AlertmanagerAlert)))
  assert len(alerts) == 2
  assert len({alert.source_id for alert in alerts}) == 2


@pytest.mark.asyncio
async def test_alertmanager_resolve_updates_existing_incident_and_is_repeat_safe(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "resolve-owner")
  project_id = await _create_project(client, owner, "Resolve project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  url = f"/webhooks/sources/{source.json()['id']}/alertmanager"
  headers = {"Authorization": f"Bearer {source.json()['credential']}"}
  firing = _alertmanager_payload(_alertmanager_alert("resolve-fingerprint"))
  resolved = _alertmanager_payload(
    _alertmanager_alert(
      "resolve-fingerprint",
      status="resolved",
      ends_at="2026-10-22T08:30:00Z",
    ),
  )

  created = await client.post(url, json=firing, headers=headers)
  incident_id = created.json()["alerts"][0]["incident_id"]
  first_resolve = await client.post(url, json=resolved, headers=headers)
  repeated_resolve = await client.post(url, json=resolved, headers=headers)

  assert first_resolve.json()["resolved"] == 1
  assert first_resolve.json()["alerts"][0]["incident_id"] == incident_id
  assert repeated_resolve.json()["updated"] == 1
  async with session_factory() as session:
    alert = await session.scalar(select(AlertmanagerAlert))
    incident = await session.get(Incident, uuid.UUID(incident_id))
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.evidence_type == "alertmanager_notification",
        ),
      ),
    )
  assert alert is not None and alert.status == "resolved"
  assert alert.starts_at.isoformat().startswith("2026-10-22T08:00:00")
  assert incident is not None and incident.status == "resolved"
  assert incident.resolved_at is not None
  assert len(evidence) == 2


@pytest.mark.asyncio
async def test_alertmanager_unmatched_resolved_alert_is_ignored(source_client):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "unmatched-owner")
  project_id = await _create_project(client, owner, "Unmatched project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  response = await client.post(
    f"/webhooks/sources/{source.json()['id']}/alertmanager",
    json=_alertmanager_payload(
      _alertmanager_alert("unknown-fingerprint", status="resolved"),
    ),
    headers={"Authorization": f"Bearer {source.json()['credential']}"},
  )

  assert response.status_code == 200
  assert response.json()["ignored"] == 1
  assert response.json()["alerts"][0]["incident_id"] is None
  async with session_factory() as session:
    assert await session.scalar(select(func.count()).select_from(AlertmanagerAlert)) == 0
    assert await session.scalar(
      select(func.count())
      .select_from(Incident)
      .where(Incident.source_type == "alertmanager"),
    ) == 0


@pytest.mark.asyncio
async def test_alertmanager_incident_stays_open_until_all_linked_alerts_resolve(
  source_client,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "multi-active-owner")
  project_id = await _create_project(client, owner, "Multi active project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  url = f"/webhooks/sources/{source.json()['id']}/alertmanager"
  headers = {"Authorization": f"Bearer {source.json()['credential']}"}
  created = await client.post(
    url,
    json=_alertmanager_payload(
      _alertmanager_alert("fingerprint-one"),
      _alertmanager_alert("fingerprint-two", name="HighMemory"),
    ),
    headers=headers,
  )
  first_alert, second_alert = created.json()["alerts"]
  async with session_factory() as session:
    second = await session.get(AlertmanagerAlert, uuid.UUID(second_alert["alert_id"]))
    second.incident_id = uuid.UUID(first_alert["incident_id"])
    await session.commit()
  manual_resolve = await client.patch(
    f"/projects/{project_id}/incidents/{first_alert['incident_id']}/status",
    json={"status": "resolved"},
    headers=_headers(owner),
  )
  assert manual_resolve.status_code == 409

  for fingerprint in ("fingerprint-one", "fingerprint-two"):
    response = await client.post(
      url,
      json=_alertmanager_payload(
        _alertmanager_alert(fingerprint, status="resolved"),
      ),
      headers=headers,
    )
    assert response.status_code == 200
    async with session_factory() as session:
      incident = await session.get(Incident, uuid.UUID(first_alert["incident_id"]))
      if fingerprint == "fingerprint-one":
        assert incident.status == "open"
      else:
        assert incident.status == "resolved"


@pytest.mark.asyncio
async def test_alertmanager_auth_payload_validation_and_source_scope(source_client):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "alertmanager-auth-owner")
  outsider = await _create_user(session_factory, "alertmanager-outsider")
  project_id = await _create_project(client, owner, "Authorized project")
  outsider_project_id = await _create_project(client, outsider, "Other project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  source_id = source.json()["id"]
  url = f"/webhooks/sources/{source_id}/alertmanager"
  valid_headers = {"Authorization": f"Bearer {source.json()['credential']}"}

  missing_auth = await client.post(
    url,
    json=_alertmanager_payload(_alertmanager_alert("secure-fingerprint")),
  )
  invalid_auth = await client.post(
    url,
    json=_alertmanager_payload(_alertmanager_alert("secure-fingerprint")),
    headers={"Authorization": "Bearer invalid"},
  )
  invalid_json = await client.post(
    url,
    content=b"{",
    headers={**valid_headers, "Content-Type": "application/json"},
  )
  malformed = await client.post(
    url,
    json={"alerts": [{"status": "firing", "fingerprint": "missing-labels"}]},
    headers=valid_headers,
  )
  accepted = await client.post(
    url,
    json={
      **_alertmanager_payload(
        _alertmanager_alert("secure-fingerprint"),
      ),
      "project_id": str(outsider_project_id),
    },
    headers=valid_headers,
  )
  incident_id = accepted.json()["alerts"][0]["incident_id"]
  cross_project = await client.get(
    f"/projects/{outsider_project_id}/incidents/{incident_id}",
    headers=_headers(outsider),
  )
  assert missing_auth.status_code == invalid_auth.status_code == 401
  assert invalid_json.status_code == 400
  assert malformed.status_code == 422
  assert accepted.status_code == 200
  assert cross_project.status_code == 404

  disabled = await client.post(
    f"/projects/{project_id}/sources/{source_id}/disable",
    headers=_headers(owner),
  )
  after_disable = await client.post(
    url,
    json=_alertmanager_payload(_alertmanager_alert("secure-fingerprint")),
    headers=valid_headers,
  )
  assert disabled.status_code == 200
  assert after_disable.status_code == 401


@pytest.mark.asyncio
async def test_alertmanager_concurrent_repeated_firing_notifications_are_idempotent(
  source_client,
):
  client, session_factory, _redis = source_client
  bind = session_factory.kw["bind"]
  if bind.dialect.name != "postgresql":
    pytest.skip("Row-lock concurrency guarantees require PostgreSQL")
  owner = await _create_user(session_factory, "concurrent-owner")
  project_id = await _create_project(client, owner, "Concurrent project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="alertmanager",
  )
  url = f"/webhooks/sources/{source.json()['id']}/alertmanager"
  headers = {"Authorization": f"Bearer {source.json()['credential']}"}
  body = _alertmanager_payload(
    _alertmanager_alert("concurrent-fingerprint"),
  )

  responses = await asyncio.gather(
    *(client.post(url, json=body, headers=headers) for _ in range(4)),
  )

  assert [response.status_code for response in responses] == [200] * 4
  async with session_factory() as session:
    alerts = list(await session.scalars(select(AlertmanagerAlert)))
    incidents = list(
      await session.scalars(
        select(Incident).where(Incident.source_type == "alertmanager"),
      ),
    )
  assert len(alerts) == 1
  assert len(incidents) == 1


@pytest.mark.asyncio
async def test_docker_source_endpoints_enforce_project_membership(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "docker-owner")
  member = await _create_user(session_factory, "docker-member")
  outsider = await _create_user(session_factory, "docker-outsider")
  project_id = await _create_project(client, owner, "Docker project")
  await _create_member(session_factory, project_id, member)
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="docker",
  )
  source_id = source.json()["id"]
  monkeypatch.setattr(
    docker_api,
    "validate_docker_connection",
    lambda: _async_result(
      {"status": "connected", "daemon_version": "27.0", "api_version": "1.47"},
    ),
  )
  monkeypatch.setattr(
    docker_api,
    "list_docker_containers",
    lambda: _async_result(
      {"containers": [], "limit": 100, "truncated": False},
    ),
  )

  validate = await client.post(
    f"/projects/{project_id}/sources/{source_id}/docker/validate",
    headers=_headers(member),
  )
  listing = await client.get(
    f"/projects/{project_id}/sources/{source_id}/docker/containers",
    headers=_headers(member),
  )
  forbidden = await client.get(
    f"/projects/{project_id}/sources/{source_id}/docker/containers",
    headers=_headers(outsider),
  )

  assert source.status_code == 201
  assert validate.status_code == 200
  assert validate.json()["status"] == "connected"
  assert listing.status_code == 200
  assert listing.json()["containers"] == []
  assert forbidden.status_code == 404


async def _async_result(result):
  return result


@pytest.mark.asyncio
async def test_docker_investigation_persists_deduplicated_incident_evidence(
  source_client,
  monkeypatch,
):
  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "docker-evidence-owner")
  project_id = await _create_project(client, owner, "Docker evidence project")
  source = await _create_source(
    client,
    project_id,
    owner,
    source_type="docker",
  )
  source_id = uuid.UUID(source.json()["id"])
  incident = await _create_labeled_test_incident(session_factory, project_id)

  is_available = True

  async def collect(source_uuid, project_uuid, container_id, log_tail_lines):
    evidence = (
      {"container": {"state": {"status": "running"}}}
      if is_available
      else None
    )
    return {
      "status": "success" if is_available else "unavailable",
      "source_id": str(source_uuid),
      "project_id": str(project_uuid),
      "container_id": container_id,
      "collected_at": "2026-01-02T03:04:05+00:00",
      "query_criteria": {
        "container_id": container_id,
        "log_tail_lines": log_tail_lines,
        "event_lookback_seconds": 300,
      },
      "query_time_range": {
        "start": "2026-01-02T02:59:05+00:00",
        "end": "2026-01-02T03:04:05+00:00",
      },
      "evidence": evidence,
      "unavailable": [] if is_available else ["daemon"],
      "errors": [] if is_available else [
        {"component": "daemon", "detail": "Docker daemon is unavailable"},
      ],
      "findings": [],
    }

  monkeypatch.setattr(docker_api, "collect_docker_investigation", collect)
  body = {
    "source_id": str(source_id),
    "incident_id": str(incident.id),
    "container_id": "a" * 64,
    "log_tail_lines": 25,
  }
  url = f"/projects/{project_id}/docker/investigations"
  first = await client.post(url, json=body, headers=_headers(owner))
  second = await client.post(url, json=body, headers=_headers(owner))
  is_available = False
  unavailable = await client.post(url, json=body, headers=_headers(owner))

  assert first.status_code == second.status_code == 200
  assert first.json()["incident_evidence_id"] == second.json()["incident_evidence_id"]
  assert unavailable.status_code == 200
  assert unavailable.json()["status"] == "unavailable"
  assert unavailable.json()["incident_evidence_id"] == first.json()["incident_evidence_id"]
  assert first.json()["query_criteria"]["log_tail_lines"] == 25
  async with session_factory() as session:
    evidence = list(
      await session.scalars(
        select(IncidentEvidence).where(
          IncidentEvidence.incident_id == incident.id,
          IncidentEvidence.evidence_type == "docker_investigation",
        ),
      ),
    )
  assert len(evidence) == 1
  assert evidence[0].incident_source_id == source_id
  assert evidence[0].normalized_content["retrieval_status"] == "unavailable"
  assert evidence[0].normalized_content["evidence_provenance"]["source_type"] == "docker"
  assert evidence[0].normalized_content["query_time_range"]["start"].startswith(
    "2026-01-02T02:59:05",
  )


@pytest.mark.asyncio
async def test_combined_incident_investigation_collects_all_available_evidence(
  source_client,
  monkeypatch,
):
  from app.core.exceptions import GitHubIntegrationError
  from app.services.loki_service import LokiQueryResult
  from app.services.trace_service import TraceQueryResult

  client, session_factory, _redis = source_client
  owner = await _create_user(session_factory, "combined-investigation-owner")
  project_id = await _create_project(
    client,
    owner,
    "Combined investigation project",
  )
  incident = await _create_labeled_test_incident(session_factory, project_id)
  trace_source_id = uuid.uuid4()
  loki_source_id = uuid.uuid4()
  docker_source_id = uuid.uuid4()
  github_event_id = uuid.uuid4()
  github_repository_id = 7654321
  async with session_factory() as session:
    session.add_all(
      [
        IncidentSource(
          id=trace_source_id,
          project_id=project_id,
          name="Combined Tempo",
          source_type="traces",
          trace_backend="tempo",
          trace_url="http://tempo.test:3200",
          trace_auth_type="none",
          trace_service_name="checkout-api",
          trace_resource_attributes={},
          credential_hash="a" * 64,
        ),
        IncidentSource(
          id=loki_source_id,
          project_id=project_id,
          name="Combined Loki",
          source_type="loki",
          loki_url="http://loki.test:3100",
          loki_auth_type="none",
          credential_hash="b" * 64,
        ),
        IncidentSource(
          id=docker_source_id,
          project_id=project_id,
          name="Combined Docker",
          source_type="docker",
          credential_hash="c" * 64,
        ),
      ],
    )
    installation = GitHubInstallation(
      project_id=project_id,
      installation_id=98765,
      account_login="example",
      status="active",
    )
    session.add(installation)
    await session.flush()
    repository = GitHubRepository(
      project_id=project_id,
      installation_id=installation.id,
      github_repo_id=github_repository_id,
      full_name="example/checkout",
      owner="example",
      html_url="https://github.com/example/checkout",
      status="active",
    )
    session.add(repository)
    await session.flush()
    session.add(
      GitHubWebhookEvent(
        id=github_event_id,
        project_id=project_id,
        github_repository_id=repository.id,
        delivery_id="combined-failed-workflow",
        event_name="workflow_run",
        action="completed",
        payload={
          "workflow_run": {
            "id": 321,
            "head_sha": "d" * 40,
            "conclusion": "failure",
          },
        },
      ),
    )
    alert_evidence = await session.scalar(
      select(IncidentEvidence).where(
        IncidentEvidence.incident_id == incident.id,
        IncidentEvidence.evidence_type == "grafana_notification",
      ),
    )
    assert alert_evidence is not None
    alert_evidence.original_content = {
      "alert": {
        "labels": {"service": "api", "environment": "test"},
        "generatorURL": "https://prometheus.example/graph",
      },
    }
    await session.commit()

  start = datetime.now(UTC) - timedelta(minutes=5)
  end = datetime.now(UTC)
  trace_id = "1" * 32
  github_available = True

  async def query_traces(_connection, query):
    return TraceQueryResult(
      status="success",
      traces=[
        {
          "trace_id": trace_id,
          "spans": [{"span_id": "2" * 16, "service_name": "checkout-api"}],
        },
      ],
      query={"trace_id": query.trace_id, "service_name": query.service_name},
      query_hash="trace-combined-query",
      start=query.start,
      end=query.end,
      retrieved_at=datetime.now(UTC),
    )

  async def query_logs(_connection, query, query_start, query_end, _limit):
    assert query == '{environment="test",service="api"}'
    return LokiQueryResult(
      status="success",
      entries=[{"timestamp": query_end.isoformat(), "line": "request failed"}],
      query=query,
      query_hash="loki-combined-query",
      start=query_start,
      end=query_end,
      retrieved_at=datetime.now(UTC),
    )

  async def collect_docker(
    source_id,
    requested_project_id,
    container_id,
    log_tail_lines,
  ):
    assert source_id == docker_source_id
    assert requested_project_id == project_id
    assert container_id == "e" * 64
    assert log_tail_lines == 50
    return {
      "status": "success",
      "source_id": str(source_id),
      "project_id": str(requested_project_id),
      "container_id": container_id,
      "collected_at": datetime.now(UTC).isoformat(),
      "query_criteria": {"container_id": container_id},
      "query_time_range": {
        "start": start.isoformat(),
        "end": end.isoformat(),
      },
      "evidence": {"container": {"state": {"status": "exited", "exit_code": 1}}},
      "unavailable": [],
      "errors": [],
      "findings": [{"code": "container_nonzero_exit"}],
    }

  async def github_context(
    _session,
    requested_project_id,
    requested_repository_id,
    requested_event_id,
    _user,
  ):
    if not github_available:
      raise GitHubIntegrationError(503, "Mock GitHub outage")
    assert requested_project_id == project_id
    assert requested_repository_id == github_repository_id
    assert requested_event_id == github_event_id
    return {
      "event_id": str(github_event_id),
      "repository": "example/checkout",
      "workflow_run": {"id": 321, "conclusion": "failure"},
      "jobs": [{"name": "tests", "conclusion": "failure"}],
      "commit": {"sha": "d" * 40},
      "code_files": [],
      "code_files_unavailable": [],
      "code_files_truncated": False,
      "commit_history": [],
      "logs": "test assertion failed",
      "logs_available": True,
      "logs_truncated": False,
    }

  monkeypatch.setattr(trace_service, "query_tempo", query_traces)
  monkeypatch.setattr(
    incident_investigation_service,
    "query_loki",
    query_logs,
  )
  monkeypatch.setattr(
    incident_investigation_service,
    "collect_docker_investigation",
    collect_docker,
  )
  monkeypatch.setattr(
    incident_investigation_service.github_project_service,
    "get_workflow_event_investigation",
    github_context,
  )

  investigation_request = {
    "traces": {
      "source_id": str(trace_source_id),
      "trace_id": trace_id,
      "start": start.isoformat(),
      "end": end.isoformat(),
    },
    "loki": {
      "source_id": str(loki_source_id),
      "start": start.isoformat(),
      "end": end.isoformat(),
      "labels": {"service": "api", "environment": "test"},
    },
    "docker": {
      "source_id": str(docker_source_id),
      "container_id": "e" * 64,
      "log_tail_lines": 50,
    },
    "github": {
      "repository_id": github_repository_id,
      "event_id": str(github_event_id),
    },
  }
  investigation_url = (
    f"/projects/{project_id}/incidents/{incident.id}/investigate"
  )
  response = await client.post(
    investigation_url,
    headers=_headers(owner),
    json=investigation_request,
  )

  assert response.status_code == 200, response.text
  result = response.json()
  assert result["integrations"]["loki"]["status"] == "success", (
    result["integrations"]["loki"]
  )
  assert {
    name: result["integrations"][name]["status"]
    for name in ("traces", "loki", "docker", "github")
  } == {
    "traces": "success",
    "loki": "success",
    "docker": "success",
    "github": "success",
  }
  assert result["status"] == "success"
  assert result["integrations"]["grafana"]["status"] == "included"
  assert result["integrations"]["prometheus"]["status"] == "not_configured"
  assert result["integrations"]["prometheus"]["detail"].startswith(
    "There is no direct Prometheus query integration.",
  )
  evidence_types = {item["evidence_type"] for item in result["evidence"]}
  assert {
    "grafana_notification",
    "trace_spans",
    "loki_logs",
    "docker_investigation",
    "github_context",
  } <= evidence_types
  grafana_evidence = next(
    item
    for item in result["evidence"]
    if item["evidence_type"] == "grafana_notification"
  )
  assert (
    grafana_evidence["original_content"]["alert"]["generatorURL"]
    == "https://prometheus.example/graph"
  )
  assert result["integrations"]["github"]["evidence_id"] in {
    item["id"]
    for item in result["evidence"]
    if item["evidence_type"] == "github_context"
  }

  github_available = False
  partial_response = await client.post(
    investigation_url,
    headers=_headers(owner),
    json=investigation_request,
  )
  assert partial_response.status_code == 200
  partial_result = partial_response.json()
  assert partial_result["status"] == "partial"
  assert partial_result["integrations"]["github"]["status"] == "unavailable"
  assert partial_result["integrations"]["traces"]["status"] == "success"
  assert partial_result["integrations"]["loki"]["status"] == "success"
  assert partial_result["integrations"]["docker"]["status"] == "success"

  github_available = True
  repeated = await client.post(
    investigation_url,
    headers=_headers(owner),
    json={
      "github": {
        "repository_id": github_repository_id,
        "event_id": str(github_event_id),
      },
    },
  )
  assert repeated.status_code == 200
  github_evidence = [
    item
    for item in repeated.json()["evidence"]
    if item["evidence_type"] == "github_context"
  ]
  assert len(github_evidence) == 1
