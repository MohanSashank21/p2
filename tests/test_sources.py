import asyncio
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
from app.db.project_membership import ProjectMembership
from app.db.redis import get_redis
from app.db.user import User
from app.main import app
from app.core.config import settings
from app.services import loki_service
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
