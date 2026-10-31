import asyncio
import errno
import hashlib
import ipaddress
import json
import math
import socket
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
  PrometheusIntegrationError,
  SourceConfigurationError,
)
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource
from app.schemas.prometheus_schema import (
  PrometheusInstantQueryRequest,
  PrometheusQueryResult,
  PrometheusRangeQueryRequest,
)


@dataclass(frozen=True)
class PrometheusConnection:
  base_url: str
  auth_type: str
  auth_ciphertext: str | None


PrometheusQueryRequest = (
  PrometheusInstantQueryRequest | PrometheusRangeQueryRequest
)


def _fernet() -> Fernet:
  configured = settings.PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY is not configured",
    )
  try:
    return Fernet(configured.get_secret_value().encode("ascii"))
  except (ValueError, UnicodeEncodeError) as error:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY is invalid",
    ) from error


def encrypt_prometheus_auth(
  auth_type: str,
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> str | None:
  if auth_type == "none":
    return None
  fernet = _fernet()
  if auth_type == "bearer" and bearer_token is not None:
    value = {"token": bearer_token.get_secret_value()}
  elif auth_type == "basic" and username is not None and password is not None:
    value = {"username": username, "password": password.get_secret_value()}
  else:
    raise PrometheusIntegrationError(
      422,
      "Invalid Prometheus authentication configuration",
    )
  return fernet.encrypt(
    json.dumps(value, separators=(",", ":")).encode("utf-8"),
  ).decode("ascii")


def _request_auth(connection: PrometheusConnection):
  if connection.auth_type == "none":
    if connection.auth_ciphertext is not None:
      raise PrometheusIntegrationError(
        503,
        "Stored Prometheus authentication configuration is invalid",
      )
    return {}, None
  if connection.auth_type not in {"bearer", "basic"}:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is invalid",
    )
  if connection.auth_ciphertext is None:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is missing",
    )
  try:
    credentials = json.loads(
      _fernet().decrypt(connection.auth_ciphertext.encode("ascii")),
    )
  except (
    InvalidToken,
    UnicodeDecodeError,
    UnicodeEncodeError,
    ValueError,
    json.JSONDecodeError,
  ) as error:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus credentials cannot be decrypted; check the encryption key",
    ) from error
  if not isinstance(credentials, dict):
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is invalid",
    )
  if (
    connection.auth_type == "bearer"
    and isinstance(credentials.get("token"), str)
    and credentials["token"]
  ):
    return {"Authorization": f"Bearer {credentials['token']}"}, None
  if (
    connection.auth_type == "basic"
    and isinstance(credentials.get("username"), str)
    and isinstance(credentials.get("password"), str)
  ):
    return {}, httpx.BasicAuth(
      credentials["username"],
      credentials["password"],
    )
  raise PrometheusIntegrationError(
    503,
    "Stored Prometheus authentication configuration is invalid",
  )


async def validate_prometheus_connection(
  connection: PrometheusConnection,
) -> None:
  validate_prometheus_url(connection.base_url)
  headers, auth = _request_auth(connection)
  timeout = httpx.Timeout(settings.PROMETHEUS_QUERY_TIMEOUT_SECONDS)
  try:
    async with httpx.AsyncClient(
      timeout=timeout,
      follow_redirects=False,
      trust_env=False,
    ) as client:
      async with client.stream(
        "GET",
        f"{connection.base_url.rstrip('/')}/-/ready",
        headers={"Accept": "text/plain", **headers},
        auth=auth,
      ) as response:
        status_code = response.status_code
  except httpx.TimeoutException as error:
    raise PrometheusIntegrationError(504, "Prometheus connection check timed out") from error
  except httpx.RequestError as error:
    raise PrometheusIntegrationError(
      502,
      "Could not connect to the configured Prometheus instance",
    ) from error
  if status_code in {401, 403}:
    raise PrometheusIntegrationError(
      502,
      "Prometheus rejected the configured credentials",
    )
  if status_code >= 500:
    raise PrometheusIntegrationError(503, "The Prometheus service is unavailable")
  if status_code < 200 or status_code >= 300:
    raise PrometheusIntegrationError(
      502,
      "Prometheus readiness endpoint returned an unexpected response",
    )


def _query_error(
  status_code: int,
  code: str,
  detail: str,
) -> PrometheusIntegrationError:
  return PrometheusIntegrationError(status_code, detail, code=code)


def _validate_query_request(
  request: PrometheusQueryRequest,
) -> tuple[int, int, int]:
  if len(request.expression) > settings.PROMETHEUS_MAX_QUERY_LENGTH:
    raise _query_error(
      422,
      "query_limit_exceeded",
      "PromQL expression exceeds the configured length limit",
    )
  timeout_seconds = min(
    request.timeout_seconds or settings.PROMETHEUS_QUERY_TIMEOUT_SECONDS,
    settings.PROMETHEUS_QUERY_TIMEOUT_SECONDS,
  )
  series_limit = min(
    request.series_limit or settings.PROMETHEUS_MAX_SERIES,
    settings.PROMETHEUS_MAX_SERIES,
  )
  if isinstance(request, PrometheusInstantQueryRequest):
    return timeout_seconds, series_limit, 1

  if request.step_seconds < settings.PROMETHEUS_MIN_QUERY_STEP_SECONDS:
    raise _query_error(
      422,
      "query_limit_exceeded",
      "Prometheus query step is below the configured minimum",
    )
  range_seconds = (request.end - request.start).total_seconds()
  if range_seconds > settings.PROMETHEUS_MAX_QUERY_RANGE_SECONDS:
    raise _query_error(
      422,
      "query_limit_exceeded",
      "Prometheus query range exceeds the configured maximum",
    )
  evaluation_points = math.floor(range_seconds / request.step_seconds) + 1
  if evaluation_points > settings.PROMETHEUS_MAX_EVALUATION_POINTS:
    raise _query_error(
      422,
      "query_limit_exceeded",
      "Prometheus query exceeds the configured evaluation-point limit",
    )
  return timeout_seconds, series_limit, evaluation_points


async def _read_bounded_response(response: httpx.Response) -> bytes:
  limit = settings.PROMETHEUS_MAX_RESPONSE_BYTES
  content_length = response.headers.get("content-length")
  if content_length is not None:
    try:
      if int(content_length) > limit:
        raise _query_error(
          502,
          "response_too_large",
          "Prometheus response exceeded the configured size limit",
        )
    except ValueError:
      pass

  content = bytearray()
  async for chunk in response.aiter_bytes():
    if len(content) + len(chunk) > limit:
      raise _query_error(
        502,
        "response_too_large",
        "Prometheus response exceeded the configured size limit",
      )
    content.extend(chunk)
  return bytes(content)


def _decode_response(content: bytes) -> dict[str, Any]:
  try:
    payload = json.loads(content)
  except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise _query_error(
      502,
      "malformed_response",
      "Prometheus returned malformed JSON",
    ) from error
  if not isinstance(payload, dict):
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an unexpected response structure",
    )
  return payload


def _raise_for_http_status(
  status_code: int,
  payload: dict[str, Any] | None = None,
) -> None:
  if status_code == 401:
    raise _query_error(
      502,
      "authentication_failed",
      "Prometheus rejected the configured credentials",
    )
  if status_code == 403:
    raise _query_error(
      502,
      "authorization_failed",
      "Prometheus denied access to the configured credentials",
    )
  if status_code == 429:
    raise _query_error(429, "upstream_rate_limited", "Prometheus rate limit was exceeded")
  if 300 <= status_code < 400:
    raise _query_error(
      502,
      "redirect_rejected",
      "Prometheus query redirects are not followed",
    )
  if status_code == 400:
    error_type = payload.get("errorType") if payload is not None else None
    if error_type == "bad_data":
      raise _query_error(
        422,
        "invalid_query",
        "Prometheus rejected the PromQL expression",
      )
    raise _query_error(
      422,
      "prometheus_api_error",
      "Prometheus rejected the query request",
    )
  if status_code >= 500:
    raise _query_error(
      503,
      "prometheus_unavailable",
      "The Prometheus service is unavailable",
    )
  if status_code < 200 or status_code >= 300:
    raise _query_error(
      502,
      "unexpected_http_status",
      "Prometheus returned an unexpected HTTP status",
    )


def _raise_for_api_error(payload: dict[str, Any]) -> None:
  error_type = payload.get("errorType")
  if not isinstance(error_type, str):
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an unexpected query error",
    )
  if error_type == "bad_data":
    raise _query_error(
      422,
      "invalid_query",
      "Prometheus rejected the PromQL expression",
    )
  if error_type in {"timeout", "canceled"}:
    raise _query_error(
      504,
      "query_timeout",
      "Prometheus did not complete the query before its server-side timeout",
    )
  if error_type == "unavailable":
    raise _query_error(
      503,
      "prometheus_unavailable",
      "The Prometheus service is unavailable",
    )
  raise _query_error(
    502,
    "prometheus_api_error",
    "Prometheus could not execute the query",
  )


def _validate_query_data(
  payload: dict[str, Any],
) -> tuple[str, Any, int, int]:
  data = payload.get("data")
  if not isinstance(data, dict):
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an unexpected query response",
    )
  result_type = data.get("resultType")
  results = data.get("result")
  if not isinstance(result_type, str) or result_type not in {
    "matrix",
    "vector",
    "scalar",
    "string",
  }:
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an unsupported result type",
    )
  if result_type in {"matrix", "vector"}:
    if not isinstance(results, list):
      raise _query_error(
        502,
        "unexpected_response",
        "Prometheus returned an invalid time-series result",
      )
    sample_count = 0
    for series in results:
      metric = series.get("metric") if isinstance(series, dict) else None
      if not isinstance(metric, dict) or any(
        not isinstance(label, str) or not isinstance(value, str)
        for label, value in metric.items()
      ):
        raise _query_error(
          502,
          "unexpected_response",
          "Prometheus returned an invalid time-series result",
        )
      if result_type == "vector":
        if not any(
          _is_sample_pair(series.get(key))
          for key in ("value", "histogram")
        ):
          raise _query_error(
            502,
            "unexpected_response",
            "Prometheus returned an invalid instant-vector sample",
          )
        sample_count += 1
      else:
        values = series.get("values", [])
        histograms = series.get("histograms", [])
        if not isinstance(values, list) or not isinstance(histograms, list):
          raise _query_error(
            502,
            "unexpected_response",
            "Prometheus returned invalid range samples",
          )
        if any(not _is_sample_pair(value) for value in values):
          raise _query_error(
            502,
            "unexpected_response",
            "Prometheus returned invalid range samples",
          )
        if any(
          not _is_sample_pair(histogram)
          for histogram in histograms
        ):
          raise _query_error(
            502,
            "unexpected_response",
            "Prometheus returned invalid range histograms",
          )
        sample_count += len(values) + len(histograms)
    return result_type, results, len(results), sample_count
  if (
    not isinstance(results, list)
    or len(results) != 2
    or isinstance(results[0], bool)
    or not isinstance(results[0], (int, float))
    or not math.isfinite(results[0])
    or not isinstance(results[1], str)
  ):
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an invalid scalar or string result",
    )
  return result_type, results, 1, 1


def _is_sample_pair(value: Any) -> bool:
  return (
    isinstance(value, list)
    and len(value) == 2
    and not isinstance(value[0], bool)
    and isinstance(value[0], (int, float))
    and math.isfinite(value[0])
    and isinstance(value[1], (str, dict))
  )


def _network_error(error: httpx.RequestError) -> PrometheusIntegrationError:
  pending: list[BaseException] = [error]
  seen: set[int] = set()
  while pending:
    current = pending.pop()
    if id(current) in seen:
      continue
    seen.add(id(current))
    if isinstance(current, socket.gaierror):
      return _query_error(
        502,
        "dns_failure",
        "Could not resolve the configured Prometheus host",
      )
    if isinstance(current, OSError) and current.errno == errno.ECONNREFUSED:
      return _query_error(
        502,
        "connection_refused",
        "The configured Prometheus host refused the connection",
      )
    if current.__cause__ is not None:
      pending.append(current.__cause__)
    if current.__context__ is not None:
      pending.append(current.__context__)
  return _query_error(
    502,
    "network_error",
    "Could not connect to the configured Prometheus instance",
  )


async def query_prometheus(
  connection: PrometheusConnection,
  request: PrometheusQueryRequest,
) -> PrometheusQueryResult:
  validate_prometheus_url(connection.base_url)
  timeout_seconds, series_limit, _evaluation_points = _validate_query_request(
    request,
  )
  headers, auth = _request_auth(connection)
  instant = isinstance(request, PrometheusInstantQueryRequest)
  endpoint = (
    "/api/v1/query" if instant else "/api/v1/query_range"
  )
  params: dict[str, str] = {
    "query": request.expression,
    "timeout": f"{timeout_seconds}s",
    "limit": str(series_limit),
  }
  if instant:
    if request.evaluation_time is not None:
      params["time"] = str(request.evaluation_time.timestamp())
  else:
    params.update(
      {
        "start": str(request.start.timestamp()),
        "end": str(request.end.timestamp()),
        "step": format(request.step_seconds, ".15g"),
      },
    )

  timeout = httpx.Timeout(
    settings.PROMETHEUS_READ_TIMEOUT_SECONDS,
    connect=settings.PROMETHEUS_CONNECT_TIMEOUT_SECONDS,
  )
  request_url = f"{connection.base_url.rstrip('/')}{endpoint}"
  try:
    async with asyncio.timeout(settings.PROMETHEUS_TOTAL_TIMEOUT_SECONDS):
      async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
      ) as client:
        async with client.stream(
          "GET",
          request_url,
          params=params,
          headers={"Accept": "application/json", **headers},
          auth=auth,
        ) as response:
          payload: dict[str, Any] | None = None
          if response.status_code == 400:
            body = await _read_bounded_response(response)
            try:
              payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
              payload = None
            if not isinstance(payload, dict):
              payload = None
          _raise_for_http_status(response.status_code, payload)
          body = await _read_bounded_response(response)
  except TimeoutError as error:
    raise _query_error(
      504,
      "query_timeout",
      "Prometheus query exceeded the configured request timeout",
    ) from error
  except httpx.TimeoutException as error:
    raise _query_error(
      504,
      "query_timeout",
      "Prometheus query timed out",
    ) from error
  except httpx.RequestError as error:
    raise _network_error(error) from error

  payload = _decode_response(body)
  if payload.get("status") == "error":
    _raise_for_api_error(payload)
  if payload.get("status") != "success":
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned an unexpected query status",
    )
  result_type, results, result_count, sample_count = _validate_query_data(
    payload,
  )
  warnings = payload.get("warnings", [])
  infos = payload.get("infos", [])
  if (
    not isinstance(warnings, list)
    or any(not isinstance(warning, str) for warning in warnings)
    or not isinstance(infos, list)
    or any(not isinstance(info, str) for info in infos)
  ):
    raise _query_error(
      502,
      "unexpected_response",
      "Prometheus returned invalid query annotations",
    )
  limit_reached = False
  if result_type in {"matrix", "vector"} and result_count > series_limit:
    results = results[:series_limit]
    result_count = len(results)
    sample_count = _count_samples(result_type, results)
    limit_reached = True
  elif result_type in {"matrix", "vector"}:
    limit_reached = result_count >= series_limit
  partial = bool(warnings) or limit_reached
  status = (
    "partial"
    if partial
    else "empty"
    if result_count == 0
    else "success"
  )
  return PrometheusQueryResult(
    status=status,
    query_type="instant" if instant else "range",
    expression=request.expression,
    evaluation_time=(
      request.evaluation_time if instant else None
    ),
    start=request.start if not instant else None,
    end=request.end if not instant else None,
    step_seconds=request.step_seconds if not instant else None,
    timeout_seconds=timeout_seconds,
    series_limit=series_limit,
    result_type=result_type,
    results=results,
    result_count=result_count,
    sample_count=sample_count,
    warnings=warnings,
    infos=infos,
    partial=partial,
    truncated=limit_reached,
  )


async def persist_prometheus_evidence(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  source_id: uuid.UUID,
  result: PrometheusQueryResult,
) -> IncidentEvidence:
  source = await session.scalar(
    select(IncidentSource)
    .where(
      IncidentSource.id == source_id,
      IncidentSource.project_id == project_id,
      IncidentSource.source_type == "prometheus",
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
  if source is None or incident is None or source.prometheus_url is None:
    raise SourceConfigurationError(
      "Prometheus source or incident changed while retrieving metrics",
    )
  stored_source_id = source.id
  stored_incident_id = incident.id
  source_endpoint = source.prometheus_url

  query_criteria: dict[str, Any] = {
    "source_id": str(stored_source_id),
    "query_type": result.query_type,
    "expression": result.expression,
    "timeout_seconds": result.timeout_seconds,
    "series_limit": result.series_limit,
  }
  if result.query_type == "instant":
    if result.evaluation_time is None:
      raise PrometheusIntegrationError(
        502,
        "Prometheus instant query is missing its evaluation time",
        code="unexpected_response",
      )
    query_criteria["evaluation_time"] = (
      result.evaluation_time.astimezone(UTC).isoformat()
    )
  else:
    if result.start is None or result.end is None or result.step_seconds is None:
      raise PrometheusIntegrationError(
        502,
        "Prometheus range query is missing its time range",
        code="unexpected_response",
      )
    query_criteria["time_range"] = {
      "start": result.start.astimezone(UTC).isoformat(),
      "end": result.end.astimezone(UTC).isoformat(),
      "step_seconds": result.step_seconds,
    }

  query_hash = hashlib.sha256(
    json.dumps(
      query_criteria,
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8"),
  ).hexdigest()
  retrieved_at = datetime.now(UTC)
  original = {
    "expression": result.expression,
    "results": result.results,
  }
  normalized = {
    "status": result.status,
    "source": "prometheus",
    "source_id": str(stored_source_id),
    "source_endpoint": source_endpoint,
    "project_id": str(project_id),
    "incident_id": str(stored_incident_id),
    "query": query_criteria,
    "query_hash": query_hash,
    "result_type": result.result_type,
    "result_count": result.result_count,
    "sample_count": result.sample_count,
    "warnings": result.warnings,
    "infos": result.infos,
    "partial": result.partial,
    "truncated": result.truncated,
    "retrieved_at": retrieved_at.isoformat(),
    "content_is_untrusted": True,
  }
  encoded = json.dumps(
    {"original": original, "normalized": normalized},
    separators=(",", ":"),
  ).encode("utf-8")
  if len(encoded) > settings.PROMETHEUS_MAX_RESPONSE_BYTES:
    raise PrometheusIntegrationError(
      502,
      "Prometheus evidence exceeded the configured response-size limit",
      code="response_too_large",
    )

  evidence = await session.scalar(
    select(IncidentEvidence).where(
      IncidentEvidence.incident_source_id == source.id,
      IncidentEvidence.incident_id == stored_incident_id,
      IncidentEvidence.query_hash == query_hash,
    ),
  )
  if evidence is None:
    evidence = IncidentEvidence(
      incident_id=stored_incident_id,
      incident_source_id=stored_source_id,
      query_hash=query_hash,
      evidence_type="prometheus_metrics",
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


def _count_samples(result_type: str, results: list[dict[str, Any]]) -> int:
  if result_type == "vector":
    return len(results)
  return sum(
    len(series.get("values", [])) + len(series.get("histograms", []))
    for series in results
  )


def validate_prometheus_url(base_url: str) -> None:
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
    raise PrometheusIntegrationError(422, "Invalid Prometheus base URL")
  try:
    port = parsed.port
  except ValueError as error:
    raise PrometheusIntegrationError(422, "Invalid Prometheus base URL port") from error
  if port == (443 if parsed.scheme == "https" else 80):
    port = None
  allowed_hosts = {
    host.strip().rstrip(".").lower()
    for host in settings.PROMETHEUS_ALLOWED_HOSTS.split(",")
    if host.strip()
  }
  if not allowed_hosts:
    raise PrometheusIntegrationError(
      503,
      "Prometheus connections are disabled until "
      "PROMETHEUS_ALLOWED_HOSTS is configured",
    )
  hostname = parsed.hostname.rstrip(".").lower()
  if port is not None:
    target = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
  else:
    target = hostname
  if target not in allowed_hosts:
    raise PrometheusIntegrationError(
      422,
      "Prometheus host is not included in the server's "
      "PROMETHEUS_ALLOWED_HOSTS",
    )
  try:
    address = ipaddress.ip_address(hostname)
  except ValueError:
    return
  if address.is_unspecified or address.is_multicast:
    raise PrometheusIntegrationError(
      422,
      "Prometheus URL cannot target this IP address",
    )
