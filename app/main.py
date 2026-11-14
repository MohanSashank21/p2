from contextlib import AsyncExitStack, asynccontextmanager
import asyncio

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.prometheus_metrics import instrument_api
from app.core.prometheus_metrics_server import start_metrics_server
from app.core.telemetry import configure_tracing
from app.db.database import AsyncSessionLocal, check_database_connection, engine
from app.api.router import api_router
from app.services.github_event_worker import run_github_event_worker
from app.services.investigation_checkpointer import (
  open_postgres_investigation_checkpointer,
)
from app.utils.jwt import validate_auth_token_configuration

@asynccontextmanager
async def lifespan(app: FastAPI):
  validate_auth_token_configuration()
  if settings.REFRESH_COOKIE_SAMESITE == "none" and not settings.REFRESH_COOKIE_SECURE:
    raise RuntimeError("REFRESH_COOKIE_SECURE must be enabled when SameSite=None")
  redis_client = Redis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True,
    socket_connect_timeout=2,
    socket_timeout=2,
    health_check_interval=30,
  )
  
  app.state.redis = redis_client
  worker_task: asyncio.Task | None = None
  metrics_server = None
  metrics_task: asyncio.Task[None] | None = None
  try:
    await redis_client.ping()
    await check_database_connection()
    metrics_server, metrics_task = await start_metrics_server()
    async with AsyncExitStack() as stack:
      if settings.AI_INVESTIGATION_ENABLED:
        app.state.investigation_checkpointer = await stack.enter_async_context(
          open_postgres_investigation_checkpointer(settings.DATABASE_URL),
        )
      worker_task = asyncio.create_task(
        run_github_event_worker(AsyncSessionLocal),
      )
      try:
        yield
      finally:
        if worker_task is not None:
          worker_task.cancel()
          try:
            await worker_task
          except asyncio.CancelledError:
            pass
        if settings.AI_INVESTIGATION_ENABLED:
          del app.state.investigation_checkpointer
  except RedisError:
    raise RuntimeError(
      "Redis is unavailable; authentication state cannot be secured",
    ) from None
  except SQLAlchemyError:
    raise RuntimeError("PostgreSQL is unavailable") from None
  finally:
    try:
      await redis_client.aclose()
    finally:
      del app.state.redis
      try:
        if metrics_server is not None and metrics_task is not None:
          metrics_server.should_exit = True
          await metrics_task
      finally:
        try:
          await engine.dispose()
        finally:
          if tracer_provider is not None:
            tracer_provider.shutdown()

app = FastAPI(
  title=settings.APP_NAME,
  version=settings.APP_VERSION,
  debug=settings.DEBUG,
  lifespan=lifespan,
)
tracer_provider = configure_tracing(app)
instrument_api(app)

if settings.cors_origins:
  app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
  )

@app.exception_handler(RedisError)
async def redis_error_handler(_request: Request, _error: RedisError) -> JSONResponse:
  return JSONResponse(
    status_code=503,
    content={"detail": "Temporary authentication storage is unavailable"},
  )

app.include_router(api_router)
