from datetime import UTC, datetime, timedelta
import errno
import json
import socket
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from app.core.config import Settings, settings
from app.core.exceptions import PrometheusIntegrationError, SourceNotFoundError
from app.db.user import User
from app.schemas.prometheus_schema import (
  PrometheusInstantQueryRequest,
  PrometheusRangeQueryRequest,
)
from app.services import prometheus_service
from app.services.prometheus_service import (
  PrometheusConnection,
  encrypt_prometheus_auth,
  query_prometheus,
)
from app.tools.contracts import ToolContext
from app.tools.registry import create_tool_registry

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _connection(
  auth_type: str = "none",
  auth_ciphertext: str | None = None,
) -> PrometheusConnection:
  return PrometheusConnection(
    base_url="http://prometheus.test:9090",
    auth_type=auth_type,
    auth_ciphertext=auth_ciphertext,
  )


def _patch_transport(monkeypatch, handler):
  def create_client(*args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(handler)
    return _REAL_ASYNC_CLIENT(*args, **kwargs)

  monkeypatch.setattr(prometheus_service.httpx, "AsyncClient", create_client)


def _vector_response(
  *series: dict,
  warnings: list[str] | None = None,
  infos: list[str] | None = None,
) -> dict:
  payload = {
    "status": "success",
    "data": {"resultType": "vector", "result": list(series)},
  }
  if warnings is not None:
    payload["warnings"] = warnings
  if infos is not None:
    payload["infos"] = infos
  return payload


@pytest.mark.asyncio
async def test_instant_query_encodes_promql_and_preserves_metric_data(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  query_expression = 'rate(http_requests_total{job="api"}[5m])'
  evaluation_time = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
  requests: list[httpx.Request] = []

  def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    return httpx.Response(
      200,
      json=_vector_response(
        {
          "metric": {"__name__": "up", "job": "api"},
          "value": [1793448000, "1"],
        },
      ),
    )

  _patch_transport(monkeypatch, handler)
  result = await query_prometheus(
    _connection(),
    PrometheusInstantQueryRequest(
      source_id=uuid.uuid4(),
      expression=query_expression,
      evaluation_time=evaluation_time,
    ),
  )

  assert requests[0].url.path == "/api/v1/query"
  assert requests[0].url.params["query"] == query_expression
  assert requests[0].url.params["time"] == str(evaluation_time.timestamp())
  assert requests[0].url.params["timeout"] == "10s"
  assert requests[0].url.params["limit"] == "100"
  assert "authorization" not in requests[0].headers
  assert result.status == "success"
  assert result.query_type == "instant"
  assert result.evaluation_time == evaluation_time
  assert result.result_type == "vector"
  assert result.result_count == result.sample_count == 1
  assert result.results[0]["metric"]["job"] == "api"
  assert result.results[0]["value"] == [1793448000, "1"]


@pytest.mark.asyncio
async def test_range_query_caps_timeout_and_series_limit(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  monkeypatch.setattr(settings, "PROMETHEUS_QUERY_TIMEOUT_SECONDS", 5)
  monkeypatch.setattr(settings, "PROMETHEUS_MAX_SERIES", 2)
  start = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
  end = start + timedelta(seconds=45)
  requests: list[httpx.Request] = []

  def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    return httpx.Response(
      200,
      json={
        "status": "success",
        "data": {
          "resultType": "matrix",
          "result": [
            {
              "metric": {"__name__": "up", "job": "api"},
              "values": [[1793448000, "1"], [1793448015, "1"]],
            },
          ],
        },
      },
    )

  _patch_transport(monkeypatch, handler)
  result = await query_prometheus(
    _connection(),
    PrometheusRangeQueryRequest(
      source_id=uuid.uuid4(),
      expression="up",
      start=start,
      end=end,
      step_seconds=15,
      timeout_seconds=60,
      series_limit=1000,
    ),
  )

  assert requests[0].url.path == "/api/v1/query_range"
  assert requests[0].url.params["query"] == "up"
  assert requests[0].url.params["start"] == str(start.timestamp())
  assert requests[0].url.params["end"] == str(end.timestamp())
  assert requests[0].url.params["step"] == "15"
  assert requests[0].url.params["timeout"] == "5s"
  assert requests[0].url.params["limit"] == "2"
  assert result.query_type == "range"
  assert result.start == start
  assert result.end == end
  assert result.step_seconds == 15
  assert result.timeout_seconds == 5
  assert result.series_limit == 2
  assert result.result_count == 1
  assert result.sample_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("auth_type", "auth_values", "expected_auth"),
  [
    ("bearer", (None, None, SecretStr("private-bearer-token")), "Bearer"),
    ("basic", ("prometheus-user", SecretStr("private-password"), None), "Basic"),
  ],
)
async def test_query_decrypts_configured_auth_without_returning_secrets(
  monkeypatch,
  auth_type,
  auth_values,
  expected_auth,
):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  key = Fernet.generate_key().decode("ascii")
  monkeypatch.setattr(
    settings,
    "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY",
    SecretStr(key),
  )
  username, password, bearer_token = auth_values
  ciphertext = encrypt_prometheus_auth(
    auth_type,
    username,
    password,
    bearer_token,
  )
  captured: list[httpx.Request] = []
  _patch_transport(
    monkeypatch,
    lambda request: (
      captured.append(request)
      or httpx.Response(
        200,
        json=_vector_response(
          {
            "metric": {"__name__": "up"},
            "value": [1793448000, "1"],
          },
        ),
      )
    ),
  )
  result = await query_prometheus(
    _connection(auth_type, ciphertext),
    PrometheusInstantQueryRequest(
      source_id=uuid.uuid4(),
      expression="up",
    ),
  )
  serialized_result = result.model_dump_json()

  assert captured[0].headers["authorization"].startswith(expected_auth)
  assert "private-bearer-token" not in serialized_result
  assert "private-password" not in serialized_result
  assert result.status == "success"


@pytest.mark.asyncio
async def test_query_returns_empty_partial_and_server_annotations(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  responses = iter(
    [
      _vector_response(),
      _vector_response(
        {"metric": {"__name__": "up"}, "value": [1793448000, "1"]},
        warnings=["Some data may be missing"],
      ),
    ],
  )
  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(200, json=next(responses)),
  )
  request = PrometheusInstantQueryRequest(
    source_id=uuid.uuid4(),
    expression="nonexistent_metric",
  )

  empty = await query_prometheus(_connection(), request)
  partial = await query_prometheus(_connection(), request)

  assert empty.status == "empty"
  assert empty.result_count == 0
  assert empty.partial is False
  assert partial.status == "partial"
  assert partial.partial is True
  assert partial.truncated is False
  assert partial.warnings == ["Some data may be missing"]


@pytest.mark.asyncio
async def test_query_marks_server_series_limit_as_potential_truncation(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  monkeypatch.setattr(settings, "PROMETHEUS_MAX_SERIES", 1)
  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(
      200,
      json=_vector_response(
        {"metric": {"__name__": "up"}, "value": [1, "1"]},
      ),
    ),
  )

  result = await query_prometheus(
    _connection(),
    PrometheusInstantQueryRequest(
      source_id=uuid.uuid4(),
      expression="up",
    ),
  )

  assert result.status == "partial"
  assert result.truncated is True
  assert result.result_count == 1


@pytest.mark.asyncio
async def test_query_enforces_series_limit_locally(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(
      200,
      json=_vector_response(
        {"metric": {"__name__": "up", "job": "api"}, "value": [1, "1"]},
        {"metric": {"__name__": "up", "job": "exporter"}, "value": [1, "1"]},
      ),
    ),
  )

  result = await query_prometheus(
    _connection(),
    PrometheusInstantQueryRequest(
      source_id=uuid.uuid4(),
      expression="up",
      series_limit=1,
    ),
  )

  assert result.result_count == 1
  assert result.sample_count == 1
  assert len(result.results) == 1
  assert result.truncated is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("status_code", "payload", "code"),
  [
    (200, {"status": "error", "errorType": "bad_data"}, "invalid_query"),
    (400, {"status": "error", "errorType": "bad_data"}, "invalid_query"),
    (401, None, "authentication_failed"),
    (403, None, "authorization_failed"),
    (429, None, "upstream_rate_limited"),
    (503, None, "prometheus_unavailable"),
  ],
)
async def test_query_maps_prometheus_and_http_errors_safely(
  monkeypatch,
  status_code,
  payload,
  code,
):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(
      status_code,
      json=payload if payload is not None else {},
    ),
  )

  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(
        source_id=uuid.uuid4(),
        expression="up{",
      ),
    )

  assert raised.value.code == code
  assert "private" not in raised.value.detail


@pytest.mark.asyncio
async def test_query_rejects_redirects_without_following_them(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  requests: list[httpx.Request] = []

  def handler(request: httpx.Request) -> httpx.Response:
    requests.append(request)
    return httpx.Response(302, headers={"Location": "http://other.test/query"})

  _patch_transport(monkeypatch, handler)
  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )

  assert raised.value.code == "redirect_rejected"
  assert len(requests) == 1


@pytest.mark.asyncio
async def test_query_bounds_streamed_response_size(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  monkeypatch.setattr(settings, "PROMETHEUS_MAX_RESPONSE_BYTES", 64)

  class OversizedStream(httpx.AsyncByteStream):
    async def __aiter__(self):
      yield b"x" * 40
      yield b"y" * 40

    async def aclose(self):
      return None

  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(200, stream=OversizedStream()),
  )
  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )

  assert raised.value.code == "response_too_large"


@pytest.mark.asyncio
async def test_query_distinguishes_timeout_and_connection_failures(monkeypatch):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")

  def timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("internal timeout detail", request=request)

  _patch_transport(monkeypatch, timeout_handler)
  with pytest.raises(PrometheusIntegrationError) as timed_out:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )
  assert timed_out.value.code == "query_timeout"
  assert "internal" not in timed_out.value.detail

  def refused_handler(request: httpx.Request) -> httpx.Response:
    error = httpx.ConnectError("connection failed", request=request)
    error.__cause__ = OSError(errno.ECONNREFUSED, "connection refused")
    raise error

  _patch_transport(monkeypatch, refused_handler)
  with pytest.raises(PrometheusIntegrationError) as refused:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )
  assert refused.value.code == "connection_refused"

  def dns_handler(request: httpx.Request) -> httpx.Response:
    error = httpx.ConnectError("connection failed", request=request)
    error.__cause__ = socket.gaierror("name resolution failed")
    raise error

  _patch_transport(monkeypatch, dns_handler)
  with pytest.raises(PrometheusIntegrationError) as dns_failure:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )
  assert dns_failure.value.code == "dns_failure"


@pytest.mark.asyncio
async def test_query_enforces_overall_request_timeout(monkeypatch):
  import asyncio

  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  monkeypatch.setattr(settings, "PROMETHEUS_TOTAL_TIMEOUT_SECONDS", 0.01)

  async def slow_handler(_request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(0.1)
    return httpx.Response(200, json=_vector_response())

  _patch_transport(monkeypatch, slow_handler)
  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )
  assert raised.value.code == "query_timeout"


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("payload", "code"),
  [
    (b"not-json", "malformed_response"),
    (
      json.dumps({"status": "success", "data": {"resultType": "unknown", "result": []}}),
      "unexpected_response",
    ),
    (
      json.dumps(
        {
          "status": "success",
          "data": {"resultType": "vector", "result": [{"value": [1, "1"]}]},
        },
      ),
      "unexpected_response",
    ),
  ],
)
async def test_query_rejects_malformed_and_unexpected_responses(
  monkeypatch,
  payload,
  code,
):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  _patch_transport(
    monkeypatch,
    lambda _request: httpx.Response(200, content=payload),
  )
  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(
      _connection(),
      PrometheusInstantQueryRequest(source_id=uuid.uuid4(), expression="up"),
    )
  assert raised.value.code == code


def test_query_schemas_reject_invalid_timestamps_steps_and_ranges():
  source_id = uuid.uuid4()
  now = datetime.now(UTC)

  with pytest.raises(ValidationError):
    PrometheusInstantQueryRequest(
      source_id=source_id,
      expression="  ",
    )
  with pytest.raises(ValidationError):
    PrometheusInstantQueryRequest(
      source_id=source_id,
      expression="up",
      evaluation_time=datetime(2026, 10, 31, 12, 0),
    )
  with pytest.raises(ValidationError):
    PrometheusRangeQueryRequest(
      source_id=source_id,
      expression="up",
      start=now,
      end=now - timedelta(minutes=1),
      step_seconds=15,
    )
  with pytest.raises(ValidationError):
    PrometheusRangeQueryRequest(
      source_id=source_id,
      expression="up",
      start=now.replace(tzinfo=None),
      end=now,
      step_seconds=15,
    )
  with pytest.raises(ValidationError):
    PrometheusRangeQueryRequest(
      source_id=source_id,
      expression="up",
      start=now,
      end=now,
      step_seconds=0,
    )


def test_prometheus_query_settings_are_validated():
  with pytest.raises(ValidationError):
    Settings(
      _env_file=None,
      DATABASE_URL="sqlite+aiosqlite://",
      PROMETHEUS_MAX_SERIES=1001,
    )
  with pytest.raises(ValidationError):
    Settings(
      _env_file=None,
      DATABASE_URL="sqlite+aiosqlite://",
      PROMETHEUS_QUERY_TIMEOUT_SECONDS=20,
      PROMETHEUS_READ_TIMEOUT_SECONDS=15,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
  ("settings_patch", "request_data", "code"),
  [
    (
      {"PROMETHEUS_MAX_QUERY_LENGTH": 3},
      {"expression": "long"},
      "query_limit_exceeded",
    ),
    (
      {"PROMETHEUS_MAX_QUERY_RANGE_SECONDS": 30},
      {
        "expression": "up",
        "start": datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
        "end": datetime(2026, 10, 31, 12, 1, tzinfo=UTC),
        "step_seconds": 15,
      },
      "query_limit_exceeded",
    ),
    (
      {"PROMETHEUS_MIN_QUERY_STEP_SECONDS": 20},
      {
        "expression": "up",
        "start": datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
        "end": datetime(2026, 10, 31, 12, 1, tzinfo=UTC),
        "step_seconds": 15,
      },
      "query_limit_exceeded",
    ),
    (
      {"PROMETHEUS_MAX_EVALUATION_POINTS": 2},
      {
        "expression": "up",
        "start": datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
        "end": datetime(2026, 10, 31, 12, 1, tzinfo=UTC),
        "step_seconds": 15,
      },
      "query_limit_exceeded",
    ),
  ],
)
async def test_query_rejects_configured_limits_before_network(
  monkeypatch,
  settings_patch,
  request_data,
  code,
):
  monkeypatch.setattr(settings, "PROMETHEUS_ALLOWED_HOSTS", "prometheus.test:9090")
  for setting, value in settings_patch.items():
    monkeypatch.setattr(settings, setting, value)
  request_data = {"source_id": uuid.uuid4(), **request_data}
  _patch_transport(
    monkeypatch,
    lambda _request: pytest.fail("Provider should not be called for invalid limits"),
  )
  model = (
    PrometheusInstantQueryRequest if "start" not in request_data
    else PrometheusRangeQueryRequest
  )
  with pytest.raises(PrometheusIntegrationError) as raised:
    await query_prometheus(_connection(), model(**request_data))
  assert raised.value.code == code


def _tool_context() -> ToolContext:
  return ToolContext(
    session=AsyncMock(),
    redis=AsyncMock(),
    project_id=uuid.uuid4(),
    incident_id=uuid.uuid4(),
    user=User(
      email="prometheus-tool@example.invalid",
      display_name="Prometheus Tool",
      password_hash="not-a-real-password-hash",
    ),
  )


@pytest.mark.asyncio
async def test_prometheus_tool_resolves_source_from_authorized_context(monkeypatch):
  context = _tool_context()
  source_id = uuid.uuid4()
  source = SimpleNamespace(
    id=source_id,
    prometheus_url="http://prometheus.test:9090",
    prometheus_auth_type="none",
    prometheus_auth_ciphertext=None,
  )
  get_source = AsyncMock(return_value=source)
  query = AsyncMock(
    return_value=prometheus_service.PrometheusQueryResult(
      status="success",
      query_type="instant",
      expression="up",
      timeout_seconds=10,
      series_limit=100,
      result_type="vector",
      results=[{"metric": {"job": "api"}, "value": [1, "1"]}],
      result_count=1,
      sample_count=1,
    ),
  )
  rate_limit = AsyncMock()
  monkeypatch.setattr(
    "app.tools.prometheus.get_project_prometheus_source",
    get_source,
  )
  monkeypatch.setattr("app.tools.prometheus.query_prometheus", query)
  monkeypatch.setattr(
    "app.tools.prometheus.rate_limit_prometheus_queries",
    rate_limit,
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )
  result = await create_tool_registry().execute(
    "prometheus.query_instant",
    {"source_id": str(source_id), "expression": "up"},
    context,
  )

  assert result.status == "success"
  assert result.content_is_untrusted is True
  assert result.data is not None
  assert result.data["results"][0]["metric"]["job"] == "api"
  call = query.await_args
  assert call is not None
  assert call.args[0] == PrometheusConnection(
    base_url=source.prometheus_url,
    auth_type="none",
    auth_ciphertext=None,
  )
  assert call.args[1].source_id == source_id
  get_source.assert_awaited_once_with(
    context.session,
    context.project_id,
    source_id,
    context.user,
  )
  rate_limit.assert_awaited_once_with(context.redis, source_id)


@pytest.mark.asyncio
async def test_prometheus_tool_does_not_query_an_unauthorized_source(monkeypatch):
  context = _tool_context()
  source_id = uuid.uuid4()
  unauthorized_source = AsyncMock(side_effect=SourceNotFoundError())
  query = AsyncMock()
  monkeypatch.setattr(
    "app.tools.prometheus.get_project_prometheus_source",
    unauthorized_source,
  )
  monkeypatch.setattr("app.tools.prometheus.query_prometheus", query)
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )

  result = await create_tool_registry().execute(
    "prometheus.query_instant",
    {"source_id": str(source_id), "expression": "up"},
    context,
  )

  assert result.status == "unavailable"
  assert result.error is not None
  assert result.error.code == "source_unavailable"
  query.assert_not_awaited()
  unauthorized_source.assert_awaited_once_with(
    context.session,
    context.project_id,
    source_id,
    context.user,
  )


@pytest.mark.asyncio
async def test_prometheus_tool_rejects_caller_supplied_endpoint(monkeypatch):
  context = _tool_context()
  source_lookup = AsyncMock()
  monkeypatch.setattr(
    "app.tools.prometheus.get_project_prometheus_source",
    source_lookup,
  )
  monkeypatch.setattr(
    "app.tools.registry.get_project_incident",
    AsyncMock(),
  )

  result = await create_tool_registry().execute(
    "prometheus.query_instant",
    {
      "source_id": str(uuid.uuid4()),
      "expression": "up",
      "prometheus_url": "http://127.0.0.1:9091",
    },
    context,
  )

  assert result.status == "error"
  assert result.error is not None
  assert result.error.code == "invalid_arguments"
  source_lookup.assert_not_awaited()
