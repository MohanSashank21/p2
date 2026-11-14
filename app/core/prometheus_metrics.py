import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI
from prometheus_client import CollectorRegistry, Counter, Histogram, make_asgi_app

ASGIMessage = dict[str, Any]
ASGIScope = dict[str, Any]
ASGIReceive = Callable[[], Awaitable[ASGIMessage]]
ASGISend = Callable[[ASGIMessage], Awaitable[None]]
ASGIApp = Callable[[ASGIScope, ASGIReceive, ASGISend], Awaitable[None]]
_ALLOWED_METHODS = frozenset(
  {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
)


class PrometheusMetricsMiddleware:
  def __init__(
    self,
    app: ASGIApp,
    *,
    requests: Counter,
    duration: Histogram,
  ) -> None:
    self.app = app
    self.requests = requests
    self.duration = duration

  async def __call__(
    self,
    scope: ASGIScope,
    receive: ASGIReceive,
    send: ASGISend,
  ) -> None:
    if scope["type"] != "http":
      await self.app(scope, receive, send)
      return

    raw_method = str(scope.get("method", "unknown")).upper()
    method = raw_method if raw_method in _ALLOWED_METHODS else "OTHER"
    status_code = 500
    started_at = time.perf_counter()

    async def record_response(message: ASGIMessage) -> None:
      nonlocal status_code
      if message["type"] == "http.response.start":
        status_code = int(message["status"])
      await send(message)

    try:
      await self.app(scope, receive, record_response)
    finally:
      route = scope.get("route")
      route_path = getattr(route, "path", "unmatched")
      self.requests.labels(
        method=method,
        route=route_path,
        status_code=str(status_code),
      ).inc()
      self.duration.labels(method=method, route=route_path).observe(
        time.perf_counter() - started_at,
      )


def create_metrics_registry() -> tuple[CollectorRegistry, Counter, Histogram]:
  registry = CollectorRegistry()
  requests = Counter(
    "opspilot_http_requests_total",
    "Total number of HTTP requests handled by the OpsPilot API.",
    ("method", "route", "status_code"),
    registry=registry,
  )
  duration = Histogram(
    "opspilot_http_request_duration_seconds",
    "Time spent handling HTTP requests in the OpsPilot API.",
    ("method", "route"),
    registry=registry,
  )
  return registry, requests, duration


_registry, _http_requests, _http_request_duration = create_metrics_registry()
metrics_app = make_asgi_app(registry=_registry)


def instrument_api(app: FastAPI) -> None:
  app.add_middleware(
    PrometheusMetricsMiddleware,
    requests=_http_requests,
    duration=_http_request_duration,
  )
