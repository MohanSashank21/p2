from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Literal

import asyncpg
import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("portfolio-test-api")

REQUESTS = Counter(
    "portfolio_test_requests_total",
    "Synthetic Portfolio test requests by route and outcome.",
    ("route", "outcome"),
)
DB_FAILURES = Counter(
    "portfolio_test_database_failures_total",
    "Synthetic test requests that could not persist because PostgreSQL was unavailable.",
)
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "local")
DEPLOYMENT_ID = os.getenv("DEPLOYMENT_ID", "portfolio-local")
VCS_REVISION = os.getenv("VCS_REVISION", "unknown")
DEPLOYMENT_ENVIRONMENT = os.getenv("DEPLOYMENT_ENVIRONMENT", "local")
BUILD_INFO = Gauge(
    "portfolio_build_info",
    "Build and deployment metadata for the Portfolio test API.",
    ("deployment_id", "service_version", "vcs_revision", "environment"),
)
BUILD_INFO.labels(
    deployment_id=DEPLOYMENT_ID,
    service_version=SERVICE_VERSION,
    vcs_revision=VCS_REVISION,
    environment=DEPLOYMENT_ENVIRONMENT,
).set(1)

LOKI_PUSH_URL = os.getenv(
    "LOKI_PUSH_URL",
    "http://loki:3100/loki/api/v1/push",
)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://portfolio_test:portfolio_test@database:5432/portfolio_test",
)
TEST_MARKER = "opspilot-portfolio-live-test"
tracer = trace.get_tracer("portfolio-test-api")


class ContactTestRequest(BaseModel):
    marker: Literal["opspilot-portfolio-live-test"] = TEST_MARKER


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if request.url.path != "/metrics":
            route = getattr(request.scope.get("route"), "path", request.url.path)
            REQUESTS.labels(
                route=route,
                outcome="error" if response.status_code >= 500 else "success",
            ).inc()
        return response


async def publish_log(
    level: str,
    message: str,
    trace_id: str,
    *,
    error_type: str | None = None,
) -> None:
    event = {
        "deployment_id": DEPLOYMENT_ID,
        "deployment_environment": DEPLOYMENT_ENVIRONMENT,
        "event": message,
        "error_type": error_type,
        "level": level,
        "marker": TEST_MARKER,
        "service": "portfolio-api",
        "service_version": SERVICE_VERSION,
        "trace_id": trace_id,
        "vcs_revision": VCS_REVISION,
        "timestamp": time.time(),
    }
    logger.log(
        logging.ERROR if level == "error" else logging.INFO,
        json.dumps(event, separators=(",", ":")),
    )
    payload = {
        "streams": [
            {
                "stream": {
                    "environment": DEPLOYMENT_ENVIRONMENT,
                    "job": "portfolio-api",
                    "ops_pilot_test": "true",
                    "scenario": "portfolio-contact-database-outage",
                    "service_name": "portfolio-api",
                    "deployment_id": DEPLOYMENT_ID,
                    "service_version": SERVICE_VERSION,
                    "vcs_revision": VCS_REVISION,
                },
                "values": [[str(time.time_ns()), json.dumps(event)]],
            },
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=2, follow_redirects=False) as client:
            response = await client.post(LOKI_PUSH_URL, json=payload)
            response.raise_for_status()
    except httpx.HTTPError:
        logger.exception("Could not push the test event to Loki")


@asynccontextmanager
async def lifespan(_: FastAPI):
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "portfolio-api",
                "service.version": SERVICE_VERSION,
                "deployment.id": DEPLOYMENT_ID,
                "deployment.environment.name": DEPLOYMENT_ENVIRONMENT,
                "vcs.revision": VCS_REVISION,
            },
        ),
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=os.getenv(
                    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    "http://tempo:4318/v1/traces",
                ),
                timeout=3,
            ),
        ),
    )
    trace.set_tracer_provider(provider)
    yield
    await asyncio.to_thread(provider.force_flush, 3000)
    await asyncio.to_thread(provider.shutdown)


app = FastAPI(
    title="Portfolio OpsPilot Test Harness",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(RequestMetricsMiddleware)
FastAPIInstrumentor.instrument_app(app)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metadata")
async def deployment_metadata() -> dict[str, str]:
    return {
        "service_name": "portfolio-api",
        "service_version": SERVICE_VERSION,
        "deployment_id": DEPLOYMENT_ID,
        "deployment_environment": DEPLOYMENT_ENVIRONMENT,
        "vcs_revision": VCS_REVISION,
    }


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/test/contact", status_code=201)
async def submit_contact_test(
    request: ContactTestRequest,
    x_opspilot_test_token: str | None = Header(default=None),
) -> dict[str, str]:
    configured_token = os.getenv("OPSPILOT_TEST_TOKEN", "")
    if (
        not configured_token
        or x_opspilot_test_token is None
        or not hmac.compare_digest(x_opspilot_test_token, configured_token)
    ):
        raise HTTPException(status_code=401, detail="Invalid test token")

    with tracer.start_as_current_span("portfolio.contact.persist") as span:
        trace_id = f"{span.get_span_context().trace_id:032x}"
        span.set_attribute("deployment.id", DEPLOYMENT_ID)
        span.set_attribute("service.version", SERVICE_VERSION)
        span.set_attribute("deployment.environment.name", DEPLOYMENT_ENVIRONMENT)
        span.set_attribute("vcs.revision", VCS_REVISION)
        span.set_attribute("db.system.name", "postgresql")
        span.set_attribute("db.namespace", "portfolio_test")
        span.set_attribute("db.operation.name", "INSERT")
        connection: asyncpg.Connection | None = None
        try:
            connection = await asyncpg.connect(DATABASE_URL, timeout=2)
            await connection.execute(
                """
                INSERT INTO contact_test_submissions (
                    marker,
                    deployment_id,
                    service_version,
                    vcs_revision,
                    trace_id
                )
                VALUES ($1, $2, $3, $4, $5)
                """,
                request.marker,
                DEPLOYMENT_ID,
                SERVICE_VERSION,
                VCS_REVISION,
                trace_id,
            )
        except (asyncpg.PostgresError, OSError, TimeoutError) as error:
            DB_FAILURES.inc()
            span.set_attribute("error.type", type(error).__name__)
            span.set_status(
                trace.Status(
                    trace.StatusCode.ERROR,
                    "Test database is unavailable",
                ),
            )
            await publish_log(
                "error",
                "test_database_unavailable",
                trace_id,
                error_type=type(error).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "test_database_unavailable",
                    "marker": TEST_MARKER,
                    "trace_id": trace_id,
                    "deployment_id": DEPLOYMENT_ID,
                    "service_version": SERVICE_VERSION,
                    "vcs_revision": VCS_REVISION,
                    "next_step": "Restart the test database and retry.",
                },
            ) from error
        finally:
            if connection is not None:
                await connection.close()

        await publish_log("info", "test_submission_stored", trace_id)
        return {
            "status": "stored",
            "marker": TEST_MARKER,
            "trace_id": trace_id,
            "deployment_id": DEPLOYMENT_ID,
            "service_version": SERVICE_VERSION,
            "vcs_revision": VCS_REVISION,
        }
