import httpx
import pytest
from fastapi import FastAPI
from prometheus_client import generate_latest

from app.core.prometheus_metrics import (
  PrometheusMetricsMiddleware,
  create_metrics_registry,
)


@pytest.mark.asyncio
async def test_http_metrics_use_route_templates_and_status_codes() -> None:
  app = FastAPI()
  registry, requests, duration = create_metrics_registry()
  app.add_middleware(
    PrometheusMetricsMiddleware,
    requests=requests,
    duration=duration,
  )

  @app.get("/incidents/{incident_id}")
  async def get_incident(incident_id: str) -> dict[str, str]:
    return {"incident_id": incident_id}

  async with httpx.AsyncClient(
    transport=httpx.ASGITransport(app=app),
    base_url="http://test",
  ) as client:
    response = await client.get("/incidents/abc")
    missing = await client.get("/missing")
    unusual_method = await client.request("CUSTOM", "/incidents/abc")

  assert response.status_code == 200
  assert missing.status_code == 404
  assert unusual_method.status_code == 405
  metrics = generate_latest(registry).decode()
  assert 'route="/incidents/{incident_id}",status_code="200"' in metrics
  assert 'route="unmatched",status_code="404"' in metrics
  assert 'method="OTHER",route="/incidents/{incident_id}",status_code="405"' in metrics
  assert "opspilot_http_request_duration_seconds_count" in metrics


@pytest.mark.asyncio
async def test_http_metrics_record_unhandled_server_errors() -> None:
  app = FastAPI()
  registry, requests, duration = create_metrics_registry()
  app.add_middleware(
    PrometheusMetricsMiddleware,
    requests=requests,
    duration=duration,
  )

  @app.get("/fail")
  async def fail() -> None:
    raise RuntimeError("expected test failure")

  async with httpx.AsyncClient(
    transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
    base_url="http://test",
  ) as client:
    response = await client.get("/fail")

  assert response.status_code == 500
  metrics = generate_latest(registry).decode()
  assert 'route="/fail",status_code="500"' in metrics
