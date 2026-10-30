import asyncio
import hashlib
import json
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import docker
from docker.errors import APIError, DockerException, NotFound
from requests.exceptions import RequestException, Timeout as RequestTimeout
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  DockerContainerNotFoundError,
  DockerIntegrationError,
  SourceConfigurationError,
)
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource

MAX_DOCKER_CONTAINERS = 100
MAX_DOCKER_EVENTS = 50
DOCKER_EVENT_LOOKBACK = timedelta(minutes=5)
DOCKER_EVENT_ACTIONS = {
  "attach",
  "commit",
  "create",
  "destroy",
  "die",
  "exec_create",
  "health_status",
  "kill",
  "oom",
  "pause",
  "rename",
  "restart",
  "start",
  "stop",
  "unpause",
}
LOG_SECRET_ASSIGNMENT = re.compile(
  r"(?i)\b([\w.-]*(?:password|passwd|pwd|token|access[_-]?key|secret|"
  r"authorization|api[_-]?key)[\w.-]*)(\s*[:=]\s*)"
  r'(?:"[^"]*"|\'[^\']*\'|[^\s,;]+)',
)
LOG_BEARER_TOKEN = re.compile(
  r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*",
)
LOG_URL_CREDENTIAL = re.compile(
  r"(?i)(://)[^:/@\s]+:[^@/\s]+@",
)
DATABASE_FAILURE = re.compile(
  r"(?i)(connection refused|could not connect|connection timed out|"
  r"database is unavailable|no route to host)",
)


def _validate_local_docker_host() -> str | None:
  host = settings.DOCKER_HOST or os.getenv("DOCKER_HOST")
  if not host:
    return None
  try:
    parsed = urlsplit(host)
  except ValueError as error:
    raise DockerIntegrationError(
      503,
      "DOCKER_HOST must be an absolute local Unix socket or Windows named pipe",
    ) from error
  if parsed.scheme == "unix":
    if parsed.netloc or not parsed.path.startswith("/") or parsed.query or parsed.fragment:
      raise DockerIntegrationError(
        503,
        "DOCKER_HOST must be an absolute local Unix socket or Windows named pipe",
      )
    return host
  if parsed.scheme == "npipe":
    if (
      parsed.netloc
      or parsed.query
      or parsed.fragment
      or not parsed.path.lower().startswith("//./pipe/")
    ):
      raise DockerIntegrationError(
        503,
        "DOCKER_HOST must be an absolute local Unix socket or Windows named pipe",
      )
    return host
  raise DockerIntegrationError(
    503,
    "Only local Unix sockets and Windows named pipes are supported; "
    "TCP Docker daemon endpoints are disabled",
  )


def create_docker_client() -> docker.DockerClient:
  host = _validate_local_docker_host()
  try:
    if host is None:
      return docker.from_env(timeout=settings.DOCKER_QUERY_TIMEOUT_SECONDS)
    return docker.DockerClient(
      base_url=host,
      version="auto",
      timeout=settings.DOCKER_QUERY_TIMEOUT_SECONDS,
    )
  except DockerException as error:
    raise DockerIntegrationError(
      503,
      "Docker daemon is unavailable; verify the local Docker Desktop/Engine connection",
    ) from error


def _safe_error(component: str, error: Exception) -> dict[str, str]:
  if isinstance(error, NotFound):
    detail = "Requested Docker object was not found"
  elif isinstance(error, APIError):
    detail = "Docker daemon could not provide this evidence"
  elif isinstance(error, (TimeoutError, RequestTimeout)):
    detail = "Docker request timed out"
  elif isinstance(error, RequestException):
    detail = "Docker request failed"
  else:
    detail = "Evidence could not be collected from Docker"
  return {"component": component, "detail": detail}


def _redact_log_text(value: str) -> str:
  value = re.sub(
    r"(?i)\b(authorization\s*:\s*)(?:bearer|basic)\s+\S+",
    r"\1[REDACTED]",
    value,
  )
  value = LOG_SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
  value = LOG_BEARER_TOKEN.sub(r"\1[REDACTED]", value)
  return LOG_URL_CREDENTIAL.sub(r"\1[REDACTED]@", value)


def redact_docker_logs(raw: bytes) -> str:
  return _redact_log_text(raw.decode("utf-8", errors="replace"))


def _container_summary(container: Any) -> dict[str, Any]:
  try:
    attrs = container.attrs or {}
  except (DockerException, RequestException) as error:
    raise DockerIntegrationError(
      503,
      "Docker daemon could not inspect the selected container",
    ) from error
  config = attrs.get("Config") or {}
  state = attrs.get("State") or {}
  image = config.get("Image") or attrs.get("Image") or "unknown"
  name = attrs.get("Name") or getattr(container, "name", "") or ""
  return {
    "container_id": str(container.id),
    "name": name.lstrip("/"),
    "image": image,
    "state": state.get("Status") or getattr(container, "status", "unknown"),
    "status": getattr(container, "status", "unknown"),
    "created_at": attrs.get("Created"),
  }


def _collect_logs(
  container: Any,
  tail_lines: int,
) -> dict[str, Any]:
  stream = container.logs(
    stream=True,
    follow=False,
    tail=tail_lines,
    timestamps=True,
    stdout=True,
    stderr=True,
  )
  chunks: list[bytes] = []
  size = 0
  truncated = False
  try:
    for chunk in stream:
      if not isinstance(chunk, bytes):
        raise ValueError("Docker returned a non-byte log chunk")
      remaining = settings.DOCKER_LOG_MAX_BYTES - size
      if remaining <= 0:
        truncated = True
        break
      chunks.append(chunk[:remaining])
      size += min(len(chunk), remaining)
      if len(chunk) > remaining:
        truncated = True
        break
  finally:
    close = getattr(stream, "close", None)
    if callable(close):
      close()
  content = redact_docker_logs(b"".join(chunks))
  return {
    "content": content,
    "tail_lines_requested": tail_lines,
    "max_bytes": settings.DOCKER_LOG_MAX_BYTES,
    "bytes_returned": size,
    "truncated": truncated,
    "content_is_untrusted": True,
  }


def _collect_stats(container: Any) -> dict[str, Any]:
  stats = container.stats(stream=False)
  cpu_stats = stats.get("cpu_stats") or {}
  previous_cpu_stats = stats.get("precpu_stats") or {}
  cpu_usage = cpu_stats.get("cpu_usage") or {}
  previous_cpu_usage = previous_cpu_stats.get("cpu_usage") or {}
  cpu_delta = cpu_usage.get("total_usage", 0) - previous_cpu_usage.get(
    "total_usage",
    0,
  )
  system_delta = cpu_stats.get("system_cpu_usage", 0) - previous_cpu_stats.get(
    "system_cpu_usage",
    0,
  )
  online_cpus = cpu_usage.get("online_cpus")
  if not isinstance(online_cpus, int) or online_cpus < 1:
    per_cpu = cpu_usage.get("percpu_usage")
    online_cpus = len(per_cpu) if isinstance(per_cpu, list) and per_cpu else 1
  cpu_percent = (
    max(0.0, cpu_delta / system_delta * online_cpus * 100)
    if cpu_delta > 0 and system_delta > 0
    else None
  )
  memory_stats = stats.get("memory_stats") or {}
  memory_usage = memory_stats.get("usage")
  memory_limit = memory_stats.get("limit")
  if not isinstance(memory_usage, int) or memory_usage < 0:
    memory_usage = None
  if not isinstance(memory_limit, int) or memory_limit <= 0:
    memory_limit = None
  return {
    "sampled_at": datetime.now(UTC).isoformat(),
    "cpu": {
      "percent": cpu_percent,
      "measurement": "instantaneous_estimate_from_current_and_previous_daemon_samples",
      "total_usage_nanos": cpu_usage.get("total_usage"),
      "total_usage_is_cumulative": True,
      "system_usage": cpu_stats.get("system_cpu_usage"),
      "system_usage_is_cumulative": True,
    },
    "memory": {
      "usage_bytes": memory_usage,
      "limit_bytes": memory_limit,
      "usage_percent": (
        memory_usage / memory_limit * 100
        if memory_usage is not None and memory_limit is not None
        else None
      ),
      "measurement": "single_instantaneous_snapshot",
    },
  }


def _safe_container_configuration(attrs: dict[str, Any]) -> dict[str, Any]:
  config = attrs.get("Config") or {}
  host_config = attrs.get("HostConfig") or {}
  restart_policy = host_config.get("RestartPolicy") or {}
  mounts = attrs.get("Mounts") or []
  safe_mounts = []
  omitted_secret_mounts = 0
  for mount in mounts:
    if not isinstance(mount, dict):
      continue
    destination = mount.get("Destination")
    if not isinstance(destination, str):
      continue
    if "secret" in destination.lower() or "credential" in destination.lower():
      omitted_secret_mounts += 1
      continue
    safe_mounts.append(
      {
        "type": mount.get("Type"),
        "destination": destination,
        "read_only": not bool(mount.get("RW", True)),
      },
    )
  return {
    "restart_policy": {
      "name": restart_policy.get("Name"),
      "maximum_retry_count": restart_policy.get("MaximumRetryCount"),
    },
    "network_mode": host_config.get("NetworkMode"),
    "read_only_root_filesystem": bool(host_config.get("ReadonlyRootfs", False)),
    "user": config.get("User"),
    "environment_variable_count": len(config.get("Env") or []),
    "environment_variable_values_included": False,
    "mounts": safe_mounts[:50],
    "omitted_secret_mount_count": omitted_secret_mounts,
    "mount_source_paths_included": False,
    "container_labels_included": False,
  }


def _collect_image_metadata(client: docker.DockerClient, attrs: dict[str, Any]) -> dict[str, Any]:
  image_id = attrs.get("Image")
  if not isinstance(image_id, str) or not image_id:
    raise ValueError("Container image ID is unavailable")
  image = client.images.get(image_id)
  image_attrs = image.attrs or {}
  rootfs = image_attrs.get("RootFS") or {}
  return {
    "image_id": image_attrs.get("Id") or image_id,
    "tags": (image_attrs.get("RepoTags") or [])[:20],
    "digests": (image_attrs.get("RepoDigests") or [])[:20],
    "created_at": image_attrs.get("Created"),
    "operating_system": image_attrs.get("Os"),
    "architecture": image_attrs.get("Architecture"),
    "layer_count": len(rootfs.get("Layers") or []),
  }


def _collect_recent_events(
  client: docker.DockerClient,
  container_id: str,
) -> list[dict[str, Any]]:
  now = datetime.now(UTC)
  since = int((now - DOCKER_EVENT_LOOKBACK).timestamp())
  until = int(now.timestamp())
  stream = client.events(
    since=since,
    until=until,
    filters={"container": container_id},
    decode=True,
  )
  events: list[dict[str, Any]] = []
  try:
    for event_index, event in enumerate(stream):
      if event_index >= MAX_DOCKER_EVENTS * 4:
        break
      if not isinstance(event, dict):
        continue
      action = event.get("Action") or event.get("status")
      if action not in DOCKER_EVENT_ACTIONS:
        continue
      actor = event.get("Actor") or {}
      event_id = actor.get("ID") if isinstance(actor, dict) else None
      if isinstance(event_id, str) and not container_id.startswith(event_id) and not event_id.startswith(container_id):
        continue
      attributes = actor.get("Attributes") if isinstance(actor, dict) else {}
      safe_attributes = {
        key: attributes[key]
        for key in ("name", "image")
        if isinstance(attributes, dict) and isinstance(attributes.get(key), str)
      }
      events.append(
        {
          "action": action,
          "time": event.get("time"),
          "time_nano": event.get("timeNano"),
          "container_id": event_id,
          "attributes": safe_attributes,
        },
      )
      if len(events) >= MAX_DOCKER_EVENTS:
        break
  finally:
    close = getattr(stream, "close", None)
    if callable(close):
      close()
  return events


def _build_findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
  findings: list[dict[str, Any]] = []
  container = evidence.get("container")
  if isinstance(container, dict):
    state = container.get("state") or {}
    if (
      state.get("status") in {"exited", "dead"}
      and isinstance(state.get("exit_code"), int)
      and state["exit_code"] != 0
    ):
      findings.append(
        {
          "code": "container_nonzero_exit",
          "severity": "warning",
          "observed": f"Container exited with code {state['exit_code']}.",
          "interpretation": "This is an observed failure signal, not a confirmed root cause.",
          "recommended_next_step": "Review the bounded container logs and the application shutdown path.",
          "evidence_paths": ["container.state.exit_code"],
        },
      )
    health = state.get("health")
    if isinstance(health, dict) and health.get("status") == "unhealthy":
      findings.append(
        {
          "code": "container_unhealthy",
          "severity": "warning",
          "observed": "Docker reports the container health check as unhealthy.",
          "interpretation": "The configured health check is failing; the check alone does not establish why.",
          "recommended_next_step": "Inspect the health-check definition and the latest application logs.",
          "evidence_paths": ["container.state.health"],
        },
      )
  logs = evidence.get("logs")
  if isinstance(logs, dict) and isinstance(logs.get("content"), str):
    if DATABASE_FAILURE.search(logs["content"]):
      findings.append(
        {
          "code": "database_connection_failure_in_logs",
          "severity": "warning",
          "observed": "Recent logs contain a database connection failure message.",
          "interpretation": "The message may indicate a database or network connection problem; it is not proof of the underlying cause.",
          "recommended_next_step": "Check database availability, host/port reachability, and non-secret connection configuration.",
          "evidence_paths": ["logs.content"],
        },
      )
  stats = evidence.get("stats")
  memory = stats.get("memory") if isinstance(stats, dict) else None
  if (
    isinstance(memory, dict)
    and isinstance(memory.get("usage_percent"), (int, float))
    and memory["usage_percent"] >= 90
  ):
    findings.append(
      {
        "code": "high_memory_usage_snapshot",
        "severity": "warning",
        "observed": f"Memory usage was {memory['usage_percent']:.1f}% of the limit in one snapshot.",
        "interpretation": "This is one high-usage sample, not evidence of a trend or spike.",
        "recommended_next_step": "Collect a time series and inspect workload memory allocation before changing limits.",
        "evidence_paths": ["stats.memory"],
      },
    )
  return findings


def _collect_investigation_sync(
  client: docker.DockerClient,
  container_id: str,
  log_tail_lines: int,
) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
  unavailable: list[str] = []
  errors: list[dict[str, str]] = []
  try:
    container = client.containers.get(container_id)
  except NotFound as error:
    raise DockerContainerNotFoundError(
      "Container was not found in the configured local Docker daemon",
    ) from error
  except (DockerException, RequestException) as error:
    raise DockerIntegrationError(
      503,
      "Docker daemon is unavailable or rejected the container inspection request",
    ) from error

  attrs = container.attrs or {}
  state = attrs.get("State") or {}
  health = state.get("Health")
  health_result = None
  if isinstance(health, dict):
    health_result = {
      "status": health.get("Status"),
      "failing_streak": health.get("FailingStreak"),
      "check_is_configured": True,
    }
  else:
    health_result = {
      "status": "not_configured",
      "failing_streak": None,
      "check_is_configured": False,
    }
  state_result = {
    "status": state.get("Status") or getattr(container, "status", "unknown"),
    "running": bool(state.get("Running", False)),
    "paused": bool(state.get("Paused", False)),
    "restarting": bool(state.get("Restarting", False)),
    "oom_killed": bool(state.get("OOMKilled", False)),
    "exit_code": state.get("ExitCode"),
    "started_at": state.get("StartedAt"),
    "finished_at": state.get("FinishedAt"),
    "health": health_result,
    "observed_transitions": [
      {"event": "started", "at": state.get("StartedAt")}
      for _ in [0]
      if state.get("StartedAt") not in {None, "", "0001-01-01T00:00:00Z"}
    ]
    + [
      {"event": "finished", "at": state.get("FinishedAt")}
      for _ in [0]
      if state.get("FinishedAt") not in {None, "", "0001-01-01T00:00:00Z"}
    ],
  }
  result: dict[str, Any] = {
    "container": {
      **_container_summary(container),
      "state": state_result,
      "restart_count": attrs.get("RestartCount"),
      "configuration": _safe_container_configuration(attrs),
    },
  }
  collectors = (
    ("logs", lambda: _collect_logs(container, log_tail_lines)),
    ("stats", lambda: _collect_stats(container)),
    ("image", lambda: _collect_image_metadata(client, attrs)),
    ("events", lambda: _collect_recent_events(client, str(container.id))),
  )
  for component, collector in collectors:
    try:
      result[component] = collector()
    except (
      DockerException,
      RequestException,
      TimeoutError,
      ValueError,
      TypeError,
      KeyError,
    ) as error:
      unavailable.append(component)
      errors.append(_safe_error(component, error))
  return result, unavailable, errors


def _investigation_payload(
  source_id: uuid.UUID,
  project_id: uuid.UUID,
  container_id: str,
  log_tail_lines: int,
  result: dict[str, Any] | None,
  unavailable: list[str],
  errors: list[dict[str, str]],
  collected_at: datetime,
) -> dict[str, Any]:
  findings = _build_findings(result or {})
  if "daemon" in unavailable:
    findings.append(
      {
        "code": "docker_daemon_unavailable",
        "severity": "warning",
        "observed": "OpsPilot could not connect to the configured local Docker daemon.",
        "interpretation": "Container evidence could not be collected.",
        "recommended_next_step": "Check that Docker Desktop/Engine is running and that the API process can access its local socket or named pipe.",
        "evidence_paths": ["errors"],
      },
    )
  if "container" in unavailable:
    findings.append(
      {
        "code": "docker_container_unavailable",
        "severity": "warning",
        "observed": "The selected container was not found or could not be inspected.",
        "interpretation": "No container-level evidence was available.",
        "recommended_next_step": "Refresh the container list and verify the selected container ID.",
        "evidence_paths": ["errors"],
      },
    )
  status = (
    "unavailable"
    if result is None
    else "partial"
    if unavailable
    else "success"
  )
  return {
    "status": status,
    "source_id": str(source_id),
    "project_id": str(project_id),
    "container_id": container_id,
    "collected_at": collected_at.isoformat(),
    "query_criteria": {
      "container_id": container_id,
      "log_tail_lines": log_tail_lines,
      "event_lookback_seconds": int(DOCKER_EVENT_LOOKBACK.total_seconds()),
    },
    "query_time_range": {
      "start": (collected_at - DOCKER_EVENT_LOOKBACK).isoformat(),
      "end": collected_at.isoformat(),
    },
    "evidence": result,
    "unavailable": unavailable,
    "errors": errors,
    "findings": findings,
  }


def _collect_with_client(
  source_id: uuid.UUID,
  project_id: uuid.UUID,
  container_id: str,
  log_tail_lines: int,
) -> dict[str, Any]:
  collected_at = datetime.now(UTC)
  try:
    client = create_docker_client()
  except DockerIntegrationError as error:
    return _investigation_payload(
      source_id,
      project_id,
      container_id,
      log_tail_lines,
      None,
      ["daemon"],
      [{"component": "daemon", "detail": error.detail}],
      collected_at,
    )
  try:
    result, unavailable, errors = _collect_investigation_sync(
      client,
      container_id,
      log_tail_lines,
    )
    return _investigation_payload(
      source_id,
      project_id,
      container_id,
      log_tail_lines,
      result,
      unavailable,
      errors,
      collected_at,
    )
  except DockerContainerNotFoundError as error:
    return _investigation_payload(
      source_id,
      project_id,
      container_id,
      log_tail_lines,
      None,
      ["container"],
      [{"component": "container", "detail": str(error)}],
      collected_at,
    )
  except DockerIntegrationError as error:
    return _investigation_payload(
      source_id,
      project_id,
      container_id,
      log_tail_lines,
      None,
      ["daemon"],
      [{"component": "daemon", "detail": error.detail}],
      collected_at,
    )
  finally:
    client.close()


async def validate_docker_connection() -> dict[str, Any]:
  def check() -> dict[str, Any]:
    client = create_docker_client()
    try:
      client.ping()
      version = client.version()
      return {
        "status": "connected",
        "daemon_version": str(version.get("Version", "unknown")),
        "api_version": version.get("ApiVersion"),
      }
    except (DockerException, RequestException) as error:
      raise DockerIntegrationError(
        503,
        "Docker daemon is unavailable; verify the local Docker Desktop/Engine connection",
      ) from error
    finally:
      client.close()

  try:
    return await asyncio.wait_for(
      asyncio.to_thread(check),
      timeout=settings.DOCKER_QUERY_TIMEOUT_SECONDS + 1,
    )
  except TimeoutError as error:
    raise DockerIntegrationError(504, "Docker daemon connection timed out") from error


async def list_docker_containers() -> dict[str, Any]:
  def list_containers() -> dict[str, Any]:
    client = create_docker_client()
    try:
      client.ping()
      containers = client.containers.list(
        all=True,
        limit=MAX_DOCKER_CONTAINERS + 1,
      )
      truncated = len(containers) > MAX_DOCKER_CONTAINERS
      summaries = [
        _container_summary(container)
        for container in containers[:MAX_DOCKER_CONTAINERS]
      ]
      return {
        "containers": summaries,
        "limit": MAX_DOCKER_CONTAINERS,
        "truncated": truncated,
      }
    except (DockerException, RequestException) as error:
      raise DockerIntegrationError(
        503,
        "Docker daemon is unavailable or could not list containers",
      ) from error
    finally:
      client.close()

  try:
    return await asyncio.wait_for(
      asyncio.to_thread(list_containers),
      timeout=settings.DOCKER_QUERY_TIMEOUT_SECONDS + 1,
    )
  except TimeoutError as error:
    raise DockerIntegrationError(504, "Docker container listing timed out") from error


async def collect_docker_investigation(
  source_id: uuid.UUID,
  project_id: uuid.UUID,
  container_id: str,
  log_tail_lines: int,
) -> dict[str, Any]:
  max_duration = settings.DOCKER_QUERY_TIMEOUT_SECONDS * 6 + 1
  try:
    return await asyncio.wait_for(
      asyncio.to_thread(
        _collect_with_client,
        source_id,
        project_id,
        container_id,
        log_tail_lines,
      ),
      timeout=max_duration,
    )
  except TimeoutError:
    collected_at = datetime.now(UTC)
    return _investigation_payload(
      source_id,
      project_id,
      container_id,
      log_tail_lines,
      None,
      ["daemon"],
      [{"component": "daemon", "detail": "Docker investigation timed out"}],
      collected_at,
    )


async def persist_docker_investigation(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  source_id: uuid.UUID,
  investigation: dict[str, Any],
  log_tail_lines: int,
) -> IncidentEvidence:
  source = await session.scalar(
    select(IncidentSource).where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "docker",
      IncidentSource.enabled.is_(True),
    ).with_for_update(),
  )
  incident = await session.scalar(
    select(Incident).where(
      Incident.id == incident_id,
      Incident.project_id == project_id,
    ),
  )
  if source is None or incident is None:
    raise SourceConfigurationError(
      "Docker source or incident changed during investigation",
    )
  query_hash = hashlib.sha256(
    json.dumps(
      {
        "source_id": str(source.id),
        "container_id": investigation["container_id"],
        "log_tail_lines": log_tail_lines,
      },
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8"),
  ).hexdigest()
  normalized = {
    **investigation,
    "retrieval_status": investigation["status"],
    "query_hash": query_hash,
    "query_criteria": investigation["query_criteria"],
    "query_time_range": investigation["query_time_range"],
    "evidence_provenance": {
      "source_id": str(source.id),
      "source_type": source.source_type,
      "incident_id": str(incident.id),
      "project_id": str(project_id),
      "collected_at": investigation["collected_at"],
      "logs_are_untrusted_input": True,
    },
  }
  original = {
    "container_id": investigation["container_id"],
    "evidence": investigation["evidence"],
    "unavailable": investigation["unavailable"],
    "errors": investigation["errors"],
    "findings": investigation["findings"],
  }
  evidence = await session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_source_id == source.id,
      IncidentEvidence.incident_id == incident.id,
      IncidentEvidence.query_hash == query_hash,
    ),
  )
  if evidence is None:
    evidence = IncidentEvidence(
      incident_id=incident.id,
      incident_source_id=source.id,
      query_hash=query_hash,
      evidence_type="docker_investigation",
      original_content=original,
      normalized_content=normalized,
    )
    session.add(evidence)
  else:
    evidence.original_content = original
    evidence.normalized_content = normalized
  try:
    await session.commit()
  except IntegrityError:
    await session.rollback()
    evidence = await session.scalar(
      select(IncidentEvidence).where(
        IncidentEvidence.incident_source_id == source.id,
        IncidentEvidence.incident_id == incident.id,
        IncidentEvidence.query_hash == query_hash,
      ),
    )
    if evidence is None:
      raise
    evidence.original_content = original
    evidence.normalized_content = normalized
    await session.commit()
  await session.refresh(evidence)
  return evidence
