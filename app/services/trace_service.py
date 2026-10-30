import hashlib
import ipaddress
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import SourceConfigurationError, TraceIntegrationError
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource
from app.services.redis_service import rate_limit_trace_queries
from redis.asyncio import Redis

MAX_TRACE_RESPONSE_BYTES = 512 * 1024
MAX_TRACE_QUERY_RANGE = 6 * 60 * 60
MAX_TRACE_RESULTS = 10
MAX_SPANS_PER_TRACE = 2_000
TRACE_ID_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})$")
TRACE_ATTRIBUTE_PATTERN = re.compile(
  r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$",
)

@dataclass(frozen=True)
class TempoConnection:
  base_url: str
  tenant_id: str | None
  auth_type: str
  auth_ciphertext: str | None


@dataclass(frozen=True)
class TraceQuery:
  trace_id: str | None
  service_name: str | None
  span_status: str | None
  resource_attributes: dict[str, Any]
  span_attributes: dict[str, Any]
  start: datetime
  end: datetime
  limit: int


@dataclass(frozen=True)
class TraceQueryResult:
  status: str
  traces: list[dict[str, Any]]
  query: dict[str, Any]
  query_hash: str
  start: datetime
  end: datetime
  retrieved_at: datetime


def validate_tempo_url(base_url: str) -> None:
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
    raise TraceIntegrationError(422, "Invalid Tempo base URL")
  try:
    port = parsed.port
  except ValueError as error:
    raise TraceIntegrationError(422, "Invalid Tempo base URL port") from error
  if port == (443 if parsed.scheme == "https" else 80):
    port = None
  allowed_hosts = {
    host.strip().rstrip(".").lower()
    for host in settings.TRACE_ALLOWED_HOSTS.split(",")
    if host.strip()
  }
  if not allowed_hosts:
    raise TraceIntegrationError(
      503,
      "Trace connections are disabled until TRACE_ALLOWED_HOSTS is configured",
    )
  hostname = parsed.hostname.rstrip(".").lower()
  if port is not None:
    target = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
  else:
    target = hostname
  if target not in allowed_hosts:
    raise TraceIntegrationError(
      422,
      "Tempo host is not included in the server's TRACE_ALLOWED_HOSTS",
    )
  try:
    address = ipaddress.ip_address(hostname)
  except ValueError:
    return
  if address.is_unspecified or address.is_multicast:
    raise TraceIntegrationError(422, "Tempo URL cannot target this IP address")


def encrypt_trace_auth(
  auth_type: str,
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> str | None:
  if auth_type == "none":
    return None
  configured = settings.TRACE_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise TraceIntegrationError(
      503,
      "TRACE_CREDENTIAL_ENCRYPTION_KEY must be configured for authenticated trace sources",
    )
  try:
    fernet = Fernet(configured.get_secret_value().encode("ascii"))
  except (ValueError, UnicodeEncodeError) as error:
    raise TraceIntegrationError(
      503,
      "TRACE_CREDENTIAL_ENCRYPTION_KEY is invalid",
    ) from error
  if auth_type == "bearer" and bearer_token is not None:
    value = {"token": bearer_token.get_secret_value()}
  elif auth_type == "basic" and username is not None and password is not None:
    value = {"username": username, "password": password.get_secret_value()}
  else:
    raise TraceIntegrationError(422, "Invalid trace authentication configuration")
  return fernet.encrypt(
    json.dumps(value, separators=(",", ":")).encode("utf-8"),
  ).decode("ascii")


def _request_headers(connection: TempoConnection) -> tuple[dict[str, str], Any]:
  headers = {"Accept": "application/json"}
  if connection.tenant_id:
    headers["X-Scope-OrgID"] = connection.tenant_id
  if connection.auth_type == "none":
    if connection.auth_ciphertext is not None:
      raise TraceIntegrationError(
        503,
        "Stored Tempo authentication configuration is invalid",
      )
    return headers, None
  if connection.auth_ciphertext is None:
    raise TraceIntegrationError(
      503,
      "Stored Tempo authentication configuration is missing",
    )
  configured = settings.TRACE_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise TraceIntegrationError(
      503,
      "TRACE_CREDENTIAL_ENCRYPTION_KEY is not configured",
    )
  try:
    fernet = Fernet(configured.get_secret_value().encode("ascii"))
    credentials = json.loads(
      fernet.decrypt(connection.auth_ciphertext.encode("ascii")),
    )
  except (
    InvalidToken,
    UnicodeDecodeError,
    UnicodeEncodeError,
    ValueError,
    json.JSONDecodeError,
  ) as error:
    raise TraceIntegrationError(
      503,
      "Stored Tempo credentials cannot be decrypted; check the encryption key",
    ) from error
  if not isinstance(credentials, dict):
    raise TraceIntegrationError(503, "Stored Tempo authentication is invalid")
  if (
    connection.auth_type == "bearer"
    and isinstance(credentials.get("token"), str)
    and credentials["token"]
  ):
    headers["Authorization"] = f"Bearer {credentials['token']}"
    return headers, None
  if (
    connection.auth_type == "basic"
    and isinstance(credentials.get("username"), str)
    and isinstance(credentials.get("password"), str)
  ):
    return headers, httpx.BasicAuth(
      credentials["username"],
      credentials["password"],
    )
  raise TraceIntegrationError(503, "Stored Tempo authentication is invalid")


def _raise_for_tempo_status(response: httpx.Response) -> None:
  if response.status_code in {401, 403}:
    raise TraceIntegrationError(502, "Tempo rejected the configured credentials")
  if response.status_code == 429:
    raise TraceIntegrationError(429, "Tempo rate limit was exceeded")
  if response.status_code == 400:
    raise TraceIntegrationError(422, "Tempo rejected the trace query")
  if response.status_code == 404:
    raise TraceIntegrationError(404, "Tempo trace or query endpoint was not found")
  if response.status_code >= 500:
    raise TraceIntegrationError(503, "The Tempo service is unavailable")
  if response.status_code < 200 or response.status_code >= 300:
    raise TraceIntegrationError(502, "Tempo returned an unexpected response")


async def _get_tempo_json(
  connection: TempoConnection,
  path: str,
  params: dict[str, str] | None = None,
) -> dict[str, Any]:
  validate_tempo_url(connection.base_url)
  headers, auth = _request_headers(connection)
  timeout = httpx.Timeout(settings.TRACE_QUERY_TIMEOUT_SECONDS)
  try:
    async with httpx.AsyncClient(
      timeout=timeout,
      follow_redirects=False,
      trust_env=False,
    ) as client:
      async with client.stream(
        "GET",
        f"{connection.base_url.rstrip('/')}{path}",
        params=params,
        headers=headers,
        auth=auth,
      ) as streamed_response:
        content = bytearray()
        if 200 <= streamed_response.status_code < 300:
          async for chunk in streamed_response.aiter_bytes():
            content.extend(chunk)
            if len(content) > MAX_TRACE_RESPONSE_BYTES:
              raise TraceIntegrationError(
                502,
                "Tempo response exceeded the 512 KiB limit",
              )
        response = httpx.Response(
          streamed_response.status_code,
          headers=streamed_response.headers,
          content=bytes(content),
          request=streamed_response.request,
        )
  except httpx.TimeoutException as error:
    raise TraceIntegrationError(504, "Tempo query timed out") from error
  except httpx.RequestError as error:
    raise TraceIntegrationError(
      502,
      "Could not connect to the configured Tempo instance",
    ) from error
  _raise_for_tempo_status(response)
  try:
    payload = response.json()
  except ValueError as error:
    raise TraceIntegrationError(502, "Tempo returned invalid JSON") from error
  if not isinstance(payload, dict):
    raise TraceIntegrationError(502, "Tempo returned an invalid response")
  return payload


async def validate_tempo_connection(connection: TempoConnection) -> None:
  payload = await _get_tempo_json(connection, "/api/status/buildinfo")
  if not isinstance(payload.get("version"), str):
    raise TraceIntegrationError(
      502,
      "Configured endpoint did not return Tempo build information",
    )


def _attribute_value(value: Any) -> Any:
  if not isinstance(value, dict):
    return value
  if isinstance(value.get("stringValue"), str):
    return value["stringValue"]
  if "intValue" in value:
    try:
      return int(value["intValue"])
    except (TypeError, ValueError):
      raise TraceIntegrationError(502, "Tempo returned an invalid span attribute")
  if "doubleValue" in value:
    try:
      number = float(value["doubleValue"])
    except (TypeError, ValueError):
      raise TraceIntegrationError(502, "Tempo returned an invalid span attribute")
    if not math.isfinite(number):
      raise TraceIntegrationError(502, "Tempo returned an invalid span attribute")
    return number
  if isinstance(value.get("boolValue"), bool):
    return value["boolValue"]
  if isinstance(value.get("arrayValue"), dict):
    values = value["arrayValue"].get("values", [])
    if not isinstance(values, list):
      raise TraceIntegrationError(502, "Tempo returned an invalid span attribute")
    return [_attribute_value(item) for item in values]
  if isinstance(value.get("kvlistValue"), dict):
    attributes = value["kvlistValue"].get("values", [])
    return _attributes(attributes)
  raise TraceIntegrationError(502, "Tempo returned an invalid span attribute")


def _attributes(value: Any) -> dict[str, Any]:
  if value is None:
    return {}
  if not isinstance(value, list):
    raise TraceIntegrationError(502, "Tempo returned invalid span attributes")
  attributes: dict[str, Any] = {}
  for item in value:
    if (
      not isinstance(item, dict)
      or not isinstance(item.get("key"), str)
      or "value" not in item
    ):
      raise TraceIntegrationError(502, "Tempo returned invalid span attributes")
    attributes[item["key"]] = _attribute_value(item["value"])
  return attributes


def _span_status(span: dict[str, Any]) -> tuple[str, str | None]:
  status = span.get("status")
  if not isinstance(status, dict):
    return "unset", None
  code = status.get("code")
  if code in (2, "2", "STATUS_CODE_ERROR", "ERROR", "error"):
    normalized = "error"
  elif code in (1, "1", "STATUS_CODE_OK", "OK", "ok"):
    normalized = "ok"
  else:
    normalized = "unset"
  message = status.get("message")
  return normalized, message if isinstance(message, str) and message else None


def normalize_tempo_trace(
  payload: dict[str, Any],
  requested_trace_id: str | None = None,
) -> dict[str, Any]:
  batches = payload.get("resourceSpans", payload.get("batches", []))
  if not isinstance(batches, list):
    raise TraceIntegrationError(502, "Tempo returned invalid trace spans")
  normalized_spans: list[dict[str, Any]] = []
  trace_id = requested_trace_id
  for batch in batches:
    if not isinstance(batch, dict):
      raise TraceIntegrationError(502, "Tempo returned invalid trace spans")
    resource = batch.get("resource")
    if resource is not None and not isinstance(resource, dict):
      raise TraceIntegrationError(502, "Tempo returned invalid trace resources")
    resource_attributes = _attributes(
      resource.get("attributes", []) if isinstance(resource, dict) else [],
    )
    service_name = resource_attributes.get("service.name")
    service_name = service_name if isinstance(service_name, str) else None
    scopes = batch.get(
      "scopeSpans",
      batch.get("instrumentationLibrarySpans", []),
    )
    if not isinstance(scopes, list):
      raise TraceIntegrationError(502, "Tempo returned invalid trace spans")
    for scope in scopes:
      if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
        raise TraceIntegrationError(502, "Tempo returned invalid trace spans")
      for span in scope["spans"]:
        if not isinstance(span, dict):
          raise TraceIntegrationError(502, "Tempo returned invalid trace spans")
        span_trace_id = span.get("traceId", span.get("traceID"))
        if span_trace_id is not None:
          if (
            not isinstance(span_trace_id, str)
            or not TRACE_ID_PATTERN.fullmatch(span_trace_id)
          ):
            raise TraceIntegrationError(502, "Tempo returned an invalid trace ID")
          if (
            requested_trace_id is not None
            and span_trace_id.lower() != requested_trace_id.lower()
          ):
            raise TraceIntegrationError(502, "Tempo returned a different trace ID")
          trace_id = trace_id or span_trace_id
        start_raw = span.get("startTimeUnixNano")
        end_raw = span.get("endTimeUnixNano")
        try:
          start_ns = int(start_raw)
          end_ns = int(end_raw)
        except (TypeError, ValueError) as error:
          raise TraceIntegrationError(
            502,
            "Tempo returned invalid span timestamps",
          ) from error
        if start_ns < 0 or end_ns < start_ns:
          raise TraceIntegrationError(
            502,
            "Tempo returned invalid span timestamps",
          )
        span_status, status_message = _span_status(span)
        span_id = span.get("spanId", span.get("spanID"))
        parent_span_id = span.get("parentSpanId", span.get("parentSpanID"))
        name = span.get("name")
        normalized_spans.append(
          {
            "trace_id": span_trace_id or requested_trace_id,
            "span_id": span_id if isinstance(span_id, str) else None,
            "parent_span_id": (
              parent_span_id if isinstance(parent_span_id, str) else None
            ),
            "service_name": service_name,
            "name": name if isinstance(name, str) else "",
            "start_time_unix_nano": str(start_ns),
            "duration_nanos": str(end_ns - start_ns),
            "duration_ms": (end_ns - start_ns) / 1_000_000,
            "status": span_status,
            "status_message": status_message,
            "attributes": _attributes(span.get("attributes", [])),
            "resource_attributes": resource_attributes,
          },
        )
        if len(normalized_spans) > MAX_SPANS_PER_TRACE:
          raise TraceIntegrationError(
            502,
            "Tempo trace exceeded the 2,000 span limit",
          )
  if trace_id is None:
    trace_id = payload.get("traceID", payload.get("traceId"))
  if not isinstance(trace_id, str) or not TRACE_ID_PATTERN.fullmatch(trace_id):
    if normalized_spans:
      trace_id = normalized_spans[0]["trace_id"]
  if not isinstance(trace_id, str) or not TRACE_ID_PATTERN.fullmatch(trace_id):
    raise TraceIntegrationError(502, "Tempo returned an invalid trace ID")
  return {"trace_id": trace_id.lower(), "spans": normalized_spans}


def _traceql_query(query: TraceQuery) -> str:
  filters: list[str] = []
  for key in (*query.resource_attributes, *query.span_attributes):
    if not TRACE_ATTRIBUTE_PATTERN.fullmatch(key):
      raise TraceIntegrationError(422, "Trace attribute name is invalid")
  if query.span_status is not None:
    filters.append(f"status={query.span_status}")
  if query.service_name:
    filters.append(
      "resource.service.name="
      + json.dumps(query.service_name, ensure_ascii=False),
    )
  for key, value in sorted(query.resource_attributes.items()):
    filters.append(
      f"resource.{key}=" + json.dumps(value, ensure_ascii=False),
    )
  for key, value in sorted(query.span_attributes.items()):
    filters.append(f"span.{key}=" + json.dumps(value, ensure_ascii=False))
  return "{ " + " && ".join(filters) + " }"


def _filter_trace_spans(
  trace: dict[str, Any],
  query: TraceQuery,
) -> None:
  trace["spans"] = [
    span
    for span in trace["spans"]
    if (
      (query.span_status is None or span["status"] == query.span_status)
      and (
        query.service_name is None
        or span["service_name"] == query.service_name
      )
      and all(
        span["resource_attributes"].get(key) == value
        for key, value in query.resource_attributes.items()
      )
      and all(
        span["attributes"].get(key) == value
        for key, value in query.span_attributes.items()
      )
    )
  ]


def _normalize_search_traces(payload: dict[str, Any]) -> list[dict[str, Any]]:
  traces = payload.get("traces")
  if not isinstance(traces, list):
    raise TraceIntegrationError(502, "Tempo returned invalid search results")
  results: list[dict[str, Any]] = []
  for item in traces:
    if not isinstance(item, dict):
      raise TraceIntegrationError(502, "Tempo returned invalid search results")
    trace_id = item.get("traceID")
    if not isinstance(trace_id, str) or not TRACE_ID_PATTERN.fullmatch(trace_id):
      raise TraceIntegrationError(502, "Tempo returned an invalid search trace ID")
    start_time = item.get("startTimeUnixNano")
    try:
      start_ns = int(start_time)
      duration_ms = float(item.get("durationMs", 0))
    except (TypeError, ValueError) as error:
      raise TraceIntegrationError(
        502,
        "Tempo returned invalid search timestamps",
      ) from error
    if start_ns < 0 or duration_ms < 0 or not math.isfinite(duration_ms):
      raise TraceIntegrationError(502, "Tempo returned invalid search timestamps")
    results.append(
      {
        "trace_id": trace_id.lower(),
        "root_service_name": item.get("rootServiceName"),
        "root_span_name": item.get("rootTraceName"),
        "start_time_unix_nano": str(start_ns),
        "duration_ms": duration_ms,
      },
    )
  return results


async def query_tempo(
  connection: TempoConnection,
  query: TraceQuery,
) -> TraceQueryResult:
  validate_tempo_url(connection.base_url)
  if query.start.tzinfo is None or query.end.tzinfo is None:
    raise TraceIntegrationError(422, "Trace query times must include a timezone")
  if query.end <= query.start:
    raise TraceIntegrationError(422, "Trace query end must be after start")
  if (query.end - query.start).total_seconds() > MAX_TRACE_QUERY_RANGE:
    raise TraceIntegrationError(422, "Trace query range cannot exceed six hours")
  if query.limit < 1 or query.limit > MAX_TRACE_RESULTS:
    raise TraceIntegrationError(422, "Trace query limit must be between 1 and 10")
  if query.trace_id is not None:
    if not TRACE_ID_PATTERN.fullmatch(query.trace_id):
      raise TraceIntegrationError(422, "Trace ID must be 16 or 32 hexadecimal characters")
    ids = [query.trace_id.lower()]
  else:
    if not (
      query.service_name
      or query.resource_attributes
      or query.span_attributes
    ):
      raise TraceIntegrationError(
        422,
        "Unfiltered trace searches are not allowed",
      )
    traceql = _traceql_query(query)
    search_payload = await _get_tempo_json(
      connection,
      "/api/search",
      params={
        "q": traceql,
        "start": str(int(query.start.timestamp())),
        "end": str(int(query.end.timestamp())),
        "limit": str(query.limit),
      },
    )
    search_results = _normalize_search_traces(search_payload)
    ids = [item["trace_id"] for item in search_results[:query.limit]]

  traces: list[dict[str, Any]] = []
  for trace_id in ids:
    try:
      payload = await _get_tempo_json(
        connection,
        f"/api/traces/{quote(trace_id, safe='')}",
        params={
          "start": str(int(query.start.timestamp())),
          "end": str(int(query.end.timestamp())),
        },
      )
    except TraceIntegrationError as error:
      if error.status_code == 404:
        continue
      raise
    trace = normalize_tempo_trace(payload, trace_id)
    _filter_trace_spans(trace, query)
    if not trace["spans"] and (
      query.trace_id is None
      or query.span_status is not None
      or query.service_name is not None
      or query.resource_attributes
      or query.span_attributes
    ):
      continue
    traces.append(trace)

  query_content = {
    "trace_id": query.trace_id.lower() if query.trace_id else None,
    "service_name": query.service_name,
    "span_status": query.span_status,
    "resource_attributes": query.resource_attributes,
    "span_attributes": query.span_attributes,
    "start": query.start.astimezone(UTC).isoformat(),
    "end": query.end.astimezone(UTC).isoformat(),
    "limit": query.limit,
  }
  query_hash = hashlib.sha256(
    json.dumps(
      {
        "query": query_content,
        "endpoint": connection.base_url,
        "tenant_id": connection.tenant_id,
      },
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8"),
  ).hexdigest()
  result = TraceQueryResult(
    status="success" if traces else "empty",
    traces=traces,
    query=query_content,
    query_hash=query_hash,
    start=query.start.astimezone(UTC),
    end=query.end.astimezone(UTC),
    retrieved_at=datetime.now(UTC),
  )
  if len(
    json.dumps(
      {"query": result.query, "traces": result.traces},
      separators=(",", ":"),
    ).encode("utf-8"),
  ) > MAX_TRACE_RESPONSE_BYTES:
    raise TraceIntegrationError(
      502,
      "Retrieved trace evidence exceeded the 512 KiB limit",
    )
  return result


async def persist_trace_evidence(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  source_id: uuid.UUID,
  result: TraceQueryResult,
) -> IncidentEvidence:
  source = await session.scalar(
    select(IncidentSource)
    .where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "traces",
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
      "Trace source or incident changed while retrieving traces",
    )
  original = {"query": result.query, "traces": result.traces}
  normalized = {
    "status": result.status,
    "backend": source.trace_backend,
    "source_id": str(source.id),
    "endpoint": source.trace_url,
    "incident_id": str(incident.id),
    "query_criteria": result.query,
    "time_range": {
      "start": result.start.isoformat(),
      "end": result.end.isoformat(),
    },
    "trace_count": len(result.traces),
    "span_count": sum(len(trace["spans"]) for trace in result.traces),
    "retrieved_at": result.retrieved_at.isoformat(),
    "query_hash": result.query_hash,
  }
  if len(
    json.dumps(
      {"original": original, "normalized": normalized},
      separators=(",", ":"),
    ).encode("utf-8"),
  ) > MAX_TRACE_RESPONSE_BYTES:
    raise TraceIntegrationError(
      502,
      "Trace evidence exceeded the 512 KiB limit",
    )
  evidence = await session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_source_id == source.id,
      IncidentEvidence.incident_id == incident.id,
      IncidentEvidence.query_hash == result.query_hash,
    ),
  )
  if evidence is None:
    evidence = IncidentEvidence(
      incident_id=incident.id,
      incident_source_id=source.id,
      query_hash=result.query_hash,
      evidence_type="trace_spans",
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


async def retrieve_incident_traces(
  session: AsyncSession,
  redis: Redis,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  source: IncidentSource,
  query: TraceQuery,
) -> tuple[TraceQueryResult, IncidentEvidence]:
  if source.trace_backend != "tempo" or source.trace_url is None:
    raise SourceConfigurationError("Trace source is not fully configured")
  await rate_limit_trace_queries(redis, source.id)
  connection = TempoConnection(
    base_url=source.trace_url,
    tenant_id=source.trace_tenant_id,
    auth_type=source.trace_auth_type or "none",
    auth_ciphertext=source.trace_auth_ciphertext,
  )
  source_id = source.id
  await session.rollback()
  result = await query_tempo(connection, query)
  evidence = await persist_trace_evidence(
    session,
    project_id,
    incident_id,
    source_id,
    result,
  )
  return result, evidence
