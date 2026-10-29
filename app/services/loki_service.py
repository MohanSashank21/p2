import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from typing import Any
import uuid
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  LokiIntegrationError,
  RateLimitExceededError,
  SourceConfigurationError,
)
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource
from app.schemas.source_schema import LokiAutomaticRetrievalResult
from app.services.redis_service import rate_limit_loki_queries
from redis.asyncio import Redis

MAX_LOKI_RESPONSE_BYTES = 512 * 1024
MAX_AUTOMATIC_SELECTOR_LABELS = 10
AUTOMATIC_LOG_LOOKBACK = timedelta(minutes=5)
MAX_AUTOMATIC_LOG_RANGE = timedelta(hours=6)


@dataclass(frozen=True)
class LokiConnection:
  base_url: str
  tenant_id: str | None
  auth_type: str
  auth_ciphertext: str | None


@dataclass(frozen=True)
class LokiQueryResult:
  status: str
  entries: list[dict[str, Any]]
  query: str
  query_hash: str
  start: datetime
  end: datetime
  retrieved_at: datetime


def _fernet() -> Fernet:
  configured = settings.LOKI_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise LokiIntegrationError(
      503,
      "LOKI_CREDENTIAL_ENCRYPTION_KEY must be configured for authenticated Loki sources",
    )
  try:
    return Fernet(configured.get_secret_value().encode("ascii"))
  except (ValueError, UnicodeEncodeError) as error:
    raise LokiIntegrationError(
      503,
      "LOKI_CREDENTIAL_ENCRYPTION_KEY is invalid",
    ) from error


def encrypt_loki_auth(
  auth_type: str,
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> str | None:
  if auth_type == "none":
    return None
  if auth_type == "bearer" and bearer_token is not None:
    value = {"token": bearer_token.get_secret_value()}
  elif auth_type == "basic" and username is not None and password is not None:
    value = {
      "username": username,
      "password": password.get_secret_value(),
    }
  else:
    raise LokiIntegrationError(422, "Invalid Loki authentication configuration")
  encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
  return _fernet().encrypt(encoded).decode("ascii")


def validate_loki_url(base_url: str) -> None:
  parsed = urlsplit(base_url)
  if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or "\\" in parsed.path
    or any(part in {".", ".."} for part in parsed.path.split("/"))
  ):
    raise LokiIntegrationError(422, "Invalid Loki base URL")
  allowed_hosts = {
    host.strip().rstrip(".").lower()
    for host in settings.LOKI_ALLOWED_HOSTS.split(",")
    if host.strip()
  }
  if not allowed_hosts:
    raise LokiIntegrationError(
      503,
      "Loki connections are disabled until LOKI_ALLOWED_HOSTS is configured",
    )
  target = parsed.hostname.rstrip(".").lower()
  if parsed.port is not None:
    target = f"{target}:{parsed.port}"
  if target not in allowed_hosts:
    raise LokiIntegrationError(
      422,
      "Loki host is not included in the server's LOKI_ALLOWED_HOSTS",
    )


def _request_auth(connection: LokiConnection):
  if connection.auth_type == "none":
    if connection.auth_ciphertext is not None:
      raise LokiIntegrationError(503, "Loki authentication configuration is invalid")
    return None
  if connection.auth_ciphertext is None:
    raise LokiIntegrationError(503, "Loki authentication configuration is missing")
  try:
    decoded = json.loads(
      _fernet().decrypt(connection.auth_ciphertext.encode("ascii")),
    )
  except (InvalidToken, UnicodeEncodeError, json.JSONDecodeError) as error:
    raise LokiIntegrationError(
      503,
      "Stored Loki credentials cannot be decrypted; check the encryption key",
    ) from error
  if not isinstance(decoded, dict):
    raise LokiIntegrationError(
      503,
      "Stored Loki authentication configuration is invalid",
    )
  if connection.auth_type == "bearer" and isinstance(decoded.get("token"), str):
    return {"Authorization": f"Bearer {decoded['token']}"}
  if (
    connection.auth_type == "basic"
    and isinstance(decoded.get("username"), str)
    and isinstance(decoded.get("password"), str)
  ):
    return httpx.BasicAuth(decoded["username"], decoded["password"])
  raise LokiIntegrationError(503, "Stored Loki authentication configuration is invalid")


def _request_headers(connection: LokiConnection) -> tuple[dict[str, str], Any]:
  headers: dict[str, str] = {}
  auth = _request_auth(connection)
  if isinstance(auth, dict):
    headers.update(auth)
    auth = None
  if connection.tenant_id:
    headers["X-Scope-OrgID"] = connection.tenant_id
  return headers, auth


def _raise_for_loki_status(response: httpx.Response) -> None:
  if response.status_code in {401, 403}:
    raise LokiIntegrationError(502, "Loki rejected the configured credentials")
  if response.status_code == 429:
    raise LokiIntegrationError(429, "Loki rate limit was exceeded")
  if response.status_code == 400:
    raise LokiIntegrationError(422, "Loki rejected the generated log selector")
  if response.status_code >= 500:
    raise LokiIntegrationError(503, "The Loki service is unavailable")
  if response.status_code < 200 or response.status_code >= 300:
    raise LokiIntegrationError(502, "Loki returned an unexpected response")
  if len(response.content) > MAX_LOKI_RESPONSE_BYTES:
    raise LokiIntegrationError(502, "Loki response exceeded the 512 KiB limit")


async def _get_loki_json(
  client: httpx.AsyncClient,
  url: str,
  params: dict[str, str],
  headers: dict[str, str],
  auth: Any,
) -> dict:
  try:
    response = await client.get(
      url,
      params=params,
      headers=headers,
      auth=auth,
    )
  except httpx.TimeoutException as error:
    raise LokiIntegrationError(504, "Loki query timed out") from error
  except httpx.RequestError as error:
    raise LokiIntegrationError(
      502,
      "Could not connect to the configured Loki instance",
    ) from error
  _raise_for_loki_status(response)
  try:
    payload = response.json()
  except ValueError as error:
    raise LokiIntegrationError(502, "Loki returned an invalid response") from error
  if not isinstance(payload, dict) or payload.get("status") != "success":
    raise LokiIntegrationError(502, "Loki returned an invalid response")
  return payload


async def discover_loki_selector_labels(
  connection: LokiConnection,
  alert_labels: dict[str, str],
  start: datetime,
  end: datetime,
) -> dict[str, str]:
  validate_loki_url(connection.base_url)
  headers, auth = _request_headers(connection)
  start_ns = str(int(start.timestamp() * 1_000_000_000))
  end_ns = str(int(end.timestamp() * 1_000_000_000))
  params = {"start": start_ns, "end": end_ns}
  url = connection.base_url.rstrip("/")
  timeout = httpx.Timeout(settings.LOKI_QUERY_TIMEOUT_SECONDS)
  try:
    async with httpx.AsyncClient(
      timeout=timeout,
      follow_redirects=False,
      trust_env=False,
    ) as client:
      payload = await _get_loki_json(
        client,
        f"{url}/loki/api/v1/labels",
        params,
        headers,
        auth,
      )
      available = payload.get("data")
      if not isinstance(available, list) or any(
        not isinstance(label, str) for label in available
      ):
        raise LokiIntegrationError(502, "Loki returned invalid label metadata")
      available_labels = set(available)
      matches: dict[str, str] = {}
      for key, value in sorted(alert_labels.items()):
        if (
          key not in available_labels
          or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None
          or not value.strip()
          or len(matches) >= MAX_AUTOMATIC_SELECTOR_LABELS
        ):
          continue
        values_payload = await _get_loki_json(
          client,
          f"{url}/loki/api/v1/label/{key}/values",
          params,
          headers,
          auth,
        )
        values = values_payload.get("data")
        if not isinstance(values, list) or any(
          not isinstance(candidate, str) for candidate in values
        ):
          raise LokiIntegrationError(502, "Loki returned invalid label values")
        if value in values:
          matches[key] = value
  except httpx.TimeoutException as error:
    raise LokiIntegrationError(504, "Loki query timed out") from error
  except httpx.RequestError as error:
    raise LokiIntegrationError(
      502,
      "Could not connect to the configured Loki instance",
    ) from error
  return matches


def _query_hash(
  connection: LokiConnection,
  query: str,
  start: datetime,
  end: datetime,
  limit: int,
) -> str:
  value = json.dumps(
    {
      "query": query,
      "base_url": connection.base_url,
      "tenant_id": connection.tenant_id,
      "start": start.isoformat(),
      "end": end.isoformat(),
      "limit": limit,
    },
    sort_keys=True,
    separators=(",", ":"),
  )
  return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def query_loki(
  connection: LokiConnection,
  query: str,
  start: datetime,
  end: datetime,
  limit: int,
) -> LokiQueryResult:
  validate_loki_url(connection.base_url)
  headers, auth = _request_headers(connection)
  url = f"{connection.base_url.rstrip('/')}/loki/api/v1/query_range"
  params = {
    "query": query,
    "start": str(int(start.timestamp() * 1_000_000_000)),
    "end": str(int(end.timestamp() * 1_000_000_000)),
    "limit": str(limit),
    "direction": "backward",
  }
  timeout = httpx.Timeout(settings.LOKI_QUERY_TIMEOUT_SECONDS)
  try:
    async with httpx.AsyncClient(
      timeout=timeout,
      follow_redirects=False,
      trust_env=False,
    ) as client:
      response = await client.get(
        url,
        params=params,
        headers=headers,
        auth=auth,
      )
  except httpx.TimeoutException as error:
    raise LokiIntegrationError(504, "Loki query timed out") from error
  except httpx.RequestError as error:
    raise LokiIntegrationError(502, "Could not connect to the configured Loki instance") from error

  _raise_for_loki_status(response)
  try:
    payload = response.json()
    streams = payload["data"]["result"]
    if payload.get("status") != "success" or not isinstance(streams, list):
      raise ValueError("invalid response shape")
    entries = []
    for stream in streams:
      if not isinstance(stream, dict):
        raise ValueError("invalid stream")
      labels = stream.get("stream")
      values = stream.get("values")
      if (
        not isinstance(labels, dict)
        or any(
          not isinstance(key, str) or not isinstance(value, str)
          for key, value in labels.items()
        )
        or not isinstance(values, list)
      ):
        raise ValueError("invalid stream")
      for item in values:
        if (
          not isinstance(item, list)
          or len(item) < 2
          or not isinstance(item[0], str)
          or not isinstance(item[1], str)
        ):
          raise ValueError("invalid log entry")
        entries.append(
          {"timestamp": item[0], "line": item[1], "labels": labels},
        )
        if len(entries) >= limit:
          break
      if len(entries) >= limit:
        break
  except (ValueError, KeyError, TypeError) as error:
    raise LokiIntegrationError(502, "Loki returned an invalid log response") from error

  serialized_entries = json.dumps(entries, separators=(",", ":"))
  if len(serialized_entries.encode("utf-8")) > MAX_LOKI_RESPONSE_BYTES:
    raise LokiIntegrationError(502, "Retrieved logs exceeded the 512 KiB limit")
  result = LokiQueryResult(
    status="success" if entries else "empty",
    entries=entries,
    query=query,
    query_hash=_query_hash(connection, query, start, end, limit),
    start=start,
    end=end,
    retrieved_at=datetime.now(UTC),
  )
  return result


async def automatically_retrieve_loki_logs(
  session: AsyncSession,
  redis: Redis,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  alert_labels: dict[str, str],
  alert_started_at: datetime,
) -> list[LokiAutomaticRetrievalResult]:
  sources = list(
    await session.scalars(
      select(IncidentSource)
      .where(
        IncidentSource.project_id == project_id,
        IncidentSource.source_type == "loki",
        IncidentSource.enabled.is_(True),
      )
      .order_by(IncidentSource.created_at, IncidentSource.id),
    ),
  )
  if not sources:
    return [
      LokiAutomaticRetrievalResult(
        status="skipped",
        detail="No enabled Loki source is configured for this project",
      ),
    ]

  now = datetime.now(UTC)
  if alert_started_at.tzinfo is None:
    alert_started_at = alert_started_at.replace(tzinfo=UTC)
  else:
    alert_started_at = alert_started_at.astimezone(UTC)
  alert_started_at = min(alert_started_at, now)
  start = max(
    alert_started_at - AUTOMATIC_LOG_LOOKBACK,
    now - MAX_AUTOMATIC_LOG_RANGE,
  )
  results: list[LokiAutomaticRetrievalResult] = []
  for source in sources:
    existing_evidence = await session.scalar(
      select(IncidentEvidence.id)
      .where(
        IncidentEvidence.incident_id == incident_id,
        IncidentEvidence.incident_source_id == source.id,
        IncidentEvidence.evidence_type == "loki_logs",
      )
      .limit(1),
    )
    if existing_evidence is not None:
      results.append(
        LokiAutomaticRetrievalResult(
          source_id=source.id,
          status="already_retrieved",
          detail="Loki evidence already exists for this source and incident",
        ),
      )
      continue

    try:
      await rate_limit_loki_queries(redis, source.id)
    except RateLimitExceededError:
      results.append(
        LokiAutomaticRetrievalResult(
          source_id=source.id,
          status="rate_limited",
          detail="Automatic Loki query rate limit was exceeded",
        ),
      )
      continue

    connection = LokiConnection(
      base_url=source.loki_url or "",
      tenant_id=source.loki_tenant_id,
      auth_type=source.loki_auth_type or "none",
      auth_ciphertext=source.loki_auth_ciphertext,
    )
    try:
      selector_labels = await discover_loki_selector_labels(
        connection,
        alert_labels,
        start,
        now,
      )
      if not selector_labels:
        results.append(
          LokiAutomaticRetrievalResult(
            source_id=source.id,
            status="skipped",
            detail=(
              "No alert label name/value pairs matched labels available in Loki"
            ),
          ),
        )
        continue
      query = "{" + ",".join(
        f"{key}={json.dumps(value, ensure_ascii=False)}"
        for key, value in sorted(selector_labels.items())
      ) + "}"
      result = await query_loki(
        connection,
        query,
        start,
        now,
        limit=200,
      )
      await persist_loki_evidence(
        session,
        project_id,
        incident_id,
        source.id,
        selector_labels,
        result,
      )
    except (LokiIntegrationError, SourceConfigurationError) as error:
      results.append(
        LokiAutomaticRetrievalResult(
          source_id=source.id,
          status="failed",
          detail=str(error.detail if isinstance(error, LokiIntegrationError) else error),
        ),
      )
      continue
    results.append(
      LokiAutomaticRetrievalResult(
        source_id=source.id,
        status=result.status,
        entry_count=len(result.entries),
      ),
    )
  return results


async def persist_loki_evidence(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  source_id: uuid.UUID,
  selector_labels: dict[str, str],
  result: LokiQueryResult,
) -> IncidentEvidence:
  source = await session.scalar(
    select(IncidentSource)
    .where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "loki",
      IncidentSource.enabled.is_(True),
    )
    .with_for_update(),
  )
  incident = await session.scalar(
    select(Incident).where(
      Incident.id == incident_id,
      Incident.project_id == project_id,
    ),
  )
  if source is None or incident is None:
    raise SourceConfigurationError(
      "Loki source or incident changed while retrieving logs",
    )
  stored_source_id = source.id
  stored_incident_id = incident.id

  original = {
    "query": result.query,
    "selector_labels": selector_labels,
    "entries": result.entries,
  }
  normalized = {
    "status": result.status,
    "source_id": str(source.id),
    "loki_url": source.loki_url,
    "tenant_id": source.loki_tenant_id,
    "time_range": {
      "start": result.start.isoformat(),
      "end": result.end.isoformat(),
    },
    "query": result.query,
    "query_hash": result.query_hash,
    "entry_count": len(result.entries),
    "retrieved_at": result.retrieved_at.isoformat(),
  }
  evidence_size = json.dumps(
    {"original": original, "normalized": normalized},
    separators=(",", ":"),
  )
  if len(evidence_size.encode("utf-8")) > MAX_LOKI_RESPONSE_BYTES:
    raise LokiIntegrationError(502, "Loki evidence exceeded the 512 KiB limit")
  evidence = await session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_source_id == stored_source_id,
      IncidentEvidence.incident_id == stored_incident_id,
      IncidentEvidence.query_hash == result.query_hash,
    ),
  )
  if evidence is None:
    evidence = IncidentEvidence(
      incident_id=stored_incident_id,
      incident_source_id=stored_source_id,
      query_hash=result.query_hash,
      evidence_type="loki_logs",
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
        IncidentEvidence.incident_source_id == stored_source_id,
        IncidentEvidence.incident_id == stored_incident_id,
        IncidentEvidence.query_hash == result.query_hash,
      ),
    )
    if evidence is None:
      raise
    evidence.original_content = original
    evidence.normalized_content = normalized
    await session.commit()
  await session.refresh(evidence)
  return evidence
