import asyncio
import os
import uuid
from copy import deepcopy

import docker
import pytest
from requests.exceptions import ReadTimeout

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

from app.core.config import settings
from app.core.exceptions import DockerIntegrationError
from app.services import docker_service


class FakeStream:
  def __init__(self, chunks):
    self.chunks = iter(chunks)
    self.closed = False

  def __iter__(self):
    return self

  def __next__(self):
    return next(self.chunks)

  def close(self):
    self.closed = True


class FakeContainer:
  id = "a" * 64
  name = "/test-api"
  status = "exited"
  attrs = {
    "Id": id,
    "Name": name,
    "Created": "2026-01-02T03:04:05Z",
    "Image": "sha256:" + "b" * 64,
    "RestartCount": 2,
    "Config": {
      "Image": "example/api:latest",
      "Env": ["DATABASE_PASSWORD=do-not-return"],
      "User": "1000",
    },
    "HostConfig": {
      "NetworkMode": "bridge",
      "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
    },
    "Mounts": [
      {
        "Type": "bind",
        "Source": "/private/source",
        "Destination": "/app/config",
        "RW": False,
      },
    ],
    "State": {
      "Status": "exited",
      "Running": False,
      "ExitCode": 1,
      "OOMKilled": False,
      "StartedAt": "2026-01-02T03:04:05Z",
      "FinishedAt": "2026-01-02T03:05:05Z",
      "Health": {"Status": "unhealthy", "FailingStreak": 2},
    },
  }

  def __init__(self, calls):
    self.calls = calls

  def logs(self, **kwargs):
    self.calls.append("logs")
    assert kwargs["tail"] == 10
    return FakeStream(
      [
        b"password=should-not-leak\n",
        b"Authorization: Bearer abcsecret\n",
        b"database connection refused\n",
      ],
    )

  def stats(self, **kwargs):
    self.calls.append("stats")
    assert kwargs == {"stream": False}
    return {
      "cpu_stats": {
        "cpu_usage": {"total_usage": 20, "online_cpus": 2},
        "system_cpu_usage": 200,
      },
      "precpu_stats": {
        "cpu_usage": {"total_usage": 10},
        "system_cpu_usage": 100,
      },
      "memory_stats": {"usage": 95, "limit": 100},
    }


class FakeContainers:
  def __init__(self, calls, container):
    self.calls = calls
    self.container = container

  def get(self, container_id):
    self.calls.append("inspect")
    assert container_id == "a" * 64
    return self.container

  def list(self, **kwargs):
    self.calls.append("list")
    assert kwargs == {"all": True, "limit": 101}
    return self.listing


class FakeImages:
  def __init__(self, calls):
    self.calls = calls

  def get(self, image_id):
    self.calls.append("image")
    assert image_id == "sha256:" + "b" * 64
    return type(
      "Image",
      (),
      {
        "attrs": {
          "Id": image_id,
          "RepoTags": ["example/api:latest"],
          "RepoDigests": [],
          "Created": "2026-01-01T00:00:00Z",
          "Os": "linux",
          "Architecture": "amd64",
          "RootFS": {"Layers": ["layer"]},
        },
      },
    )()


class FakeDockerClient:
  def __init__(self, container=None):
    self.calls = []
    self.container = container or FakeContainer(self.calls)
    self.containers = FakeContainers(self.calls, self.container)
    self.containers.listing = [self.container]
    self.images = FakeImages(self.calls)
    self.closed = False

  def ping(self):
    self.calls.append("ping")

  def version(self):
    self.calls.append("version")
    return {"Version": "27.0", "ApiVersion": "1.47"}

  def events(self, **kwargs):
    self.calls.append("events")
    assert kwargs["filters"] == {"container": "a" * 64}
    assert 0 < kwargs["until"] - kwargs["since"] <= 300
    return FakeStream(
      [
        {
          "Action": "die",
          "time": 1767323100,
          "Actor": {
            "ID": "a" * 64,
            "Attributes": {"name": "test-api", "image": "example/api:latest"},
          },
        },
      ],
    )

  def close(self):
    self.closed = True


def test_docker_host_validation_accepts_local_sockets_and_rejects_tcp(monkeypatch):
  monkeypatch.delenv("DOCKER_HOST", raising=False)
  monkeypatch.setattr(settings, "DOCKER_HOST", "")
  assert docker_service._validate_local_docker_host() is None

  monkeypatch.setattr(settings, "DOCKER_HOST", "unix:///var/run/docker.sock")
  assert docker_service._validate_local_docker_host() == "unix:///var/run/docker.sock"

  monkeypatch.setattr(
    settings,
    "DOCKER_HOST",
    "npipe:////./pipe/docker_engine",
  )
  assert docker_service._validate_local_docker_host() == "npipe:////./pipe/docker_engine"

  for unsafe_host in (
    "tcp://127.0.0.1:2375",
    "tcp://docker.example:2375",
    "npipe://remote/pipe/docker_engine",
  ):
    monkeypatch.setattr(settings, "DOCKER_HOST", unsafe_host)
    with pytest.raises(DockerIntegrationError):
      docker_service._validate_local_docker_host()


@pytest.mark.asyncio
async def test_connection_validation_uses_daemon_read_operations(monkeypatch):
  fake = FakeDockerClient()
  monkeypatch.setattr(docker_service, "create_docker_client", lambda: fake)

  result = await docker_service.validate_docker_connection()

  assert result == {
    "status": "connected",
    "daemon_version": "27.0",
    "api_version": "1.47",
  }
  assert fake.calls == ["ping", "version"]
  assert fake.closed is True


def test_log_collection_bounds_bytes_and_redacts_secrets(monkeypatch):
  monkeypatch.setattr(settings, "DOCKER_LOG_MAX_BYTES", 32)
  stream = FakeStream([b"password=supersecret " + b"x" * 50])
  container = type("Container", (), {"logs": lambda self, **_kwargs: stream})()

  result = docker_service._collect_logs(container, 5)

  assert result["bytes_returned"] == 32
  assert result["truncated"] is True
  assert "supersecret" not in result["content"]
  assert stream.closed is True


def test_log_redaction_handles_common_secret_key_names_and_url_credentials():
  value = (
    "client_secret=private refresh_token: hidden "
    "https://private-user:private-password@example.test/path"
  )

  redacted = docker_service._redact_log_text(value)

  assert "private" not in redacted
  assert "hidden" not in redacted
  assert "private-user" not in redacted
  assert "private-password" not in redacted


@pytest.mark.asyncio
async def test_successful_investigation_normalizes_safe_bounded_evidence(monkeypatch):
  fake = FakeDockerClient()
  monkeypatch.setattr(docker_service, "create_docker_client", lambda: fake)
  monkeypatch.setattr(settings, "DOCKER_LOG_MAX_BYTES", 4096)

  result = await docker_service.collect_docker_investigation(
    uuid.uuid4(),
    uuid.uuid4(),
    "a" * 64,
    10,
  )

  assert result["status"] == "success"
  assert result["evidence"]["container"]["state"]["exit_code"] == 1
  assert result["evidence"]["container"]["state"]["health"]["status"] == "unhealthy"
  assert result["evidence"]["container"]["configuration"]["environment_variable_values_included"] is False
  assert result["evidence"]["container"]["configuration"]["mounts"][0]["destination"] == "/app/config"
  assert result["evidence"]["container"]["configuration"]["mounts"][0].get("source") is None
  logs = result["evidence"]["logs"]["content"]
  assert "should-not-leak" not in logs
  assert "abcsecret" not in logs
  assert "connection refused" in logs
  assert any(item["code"] == "container_nonzero_exit" for item in result["findings"])
  assert any(item["code"] == "container_unhealthy" for item in result["findings"])
  assert any(item["code"] == "database_connection_failure_in_logs" for item in result["findings"])
  assert any(item["code"] == "high_memory_usage_snapshot" for item in result["findings"])
  assert result["query_criteria"]["event_lookback_seconds"] == 300
  assert {"inspect", "logs", "stats", "image", "events"}.issubset(fake.calls)
  assert fake.closed is True
  assert not any("start" in call or "stop" in call or "exec" in call for call in fake.calls)


@pytest.mark.asyncio
async def test_missing_container_and_daemon_failure_return_structured_results(monkeypatch):
  missing_client = FakeDockerClient()

  def missing_container(_container_id):
    raise docker.errors.NotFound("missing")

  missing_client.containers.get = missing_container
  monkeypatch.setattr(
    docker_service,
    "create_docker_client",
    lambda: missing_client,
  )
  missing = await docker_service.collect_docker_investigation(
    uuid.uuid4(),
    uuid.uuid4(),
    "a" * 64,
    10,
  )
  assert missing["status"] == "unavailable"
  assert "container" in missing["unavailable"]
  assert missing_client.closed is True

  def unavailable_client():
    raise DockerIntegrationError(503, "daemon not available")

  monkeypatch.setattr(docker_service, "create_docker_client", unavailable_client)
  unavailable = await docker_service.collect_docker_investigation(
    uuid.uuid4(),
    uuid.uuid4(),
    "a" * 64,
    10,
  )
  assert unavailable["status"] == "unavailable"
  assert "daemon" in unavailable["unavailable"]


@pytest.mark.asyncio
async def test_container_listing_is_limited_and_closes_client(monkeypatch):
  fake = FakeDockerClient()
  fake.containers.listing = [
    FakeContainer(fake.calls) for _ in range(101)
  ]
  monkeypatch.setattr(docker_service, "create_docker_client", lambda: fake)
  result = await docker_service.list_docker_containers()

  assert result["limit"] == 100
  assert result["truncated"] is True
  assert len(result["containers"]) == 100
  assert fake.calls == ["ping", "list"]
  assert fake.closed is True


@pytest.mark.asyncio
async def test_running_container_without_health_check_is_normalized(monkeypatch):
  fake = FakeDockerClient()
  fake.container.attrs = deepcopy(fake.container.attrs)
  fake.container.attrs["State"] = {
    "Status": "running",
    "Running": True,
    "ExitCode": 0,
  }
  fake.container.status = "running"
  fake.container.logs = lambda **_kwargs: FakeStream([b"service ready\n"])
  fake.container.stats = lambda **_kwargs: {
    "cpu_stats": {},
    "precpu_stats": {},
    "memory_stats": {"usage": 5, "limit": 100},
  }
  monkeypatch.setattr(docker_service, "create_docker_client", lambda: fake)

  result = await docker_service.collect_docker_investigation(
    uuid.uuid4(),
    uuid.uuid4(),
    "a" * 64,
    10,
  )

  assert result["status"] == "success"
  container = result["evidence"]["container"]
  assert container["state"]["running"] is True
  assert container["state"]["health"]["status"] == "not_configured"
  assert result["findings"] == []


@pytest.mark.asyncio
async def test_read_timeouts_are_reported_as_partial_evidence(monkeypatch):
  fake = FakeDockerClient()
  fake.container.stats = lambda **_kwargs: (_ for _ in ()).throw(ReadTimeout())
  monkeypatch.setattr(docker_service, "create_docker_client", lambda: fake)

  result = await docker_service.collect_docker_investigation(
    uuid.uuid4(),
    uuid.uuid4(),
    "a" * 64,
    10,
  )

  assert result["status"] == "partial"
  assert "stats" in result["unavailable"]
  assert result["errors"][0]["detail"] == "Docker request timed out"


@pytest.mark.asyncio
async def test_container_listing_timeout_returns_gateway_timeout(monkeypatch):
  monkeypatch.setattr(settings, "DOCKER_QUERY_TIMEOUT_SECONDS", 1)

  async def slow_to_thread(*_args, **_kwargs):
    await asyncio.sleep(10)

  monkeypatch.setattr(docker_service.asyncio, "to_thread", slow_to_thread)

  with pytest.raises(DockerIntegrationError) as error:
    await docker_service.list_docker_containers()

  assert error.value.status_code == 504
