from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.database import check_database_connection, engine
from app.api.router import api_router
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
  try:
    await redis_client.ping()
    await check_database_connection()
    yield
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
      await engine.dispose()

app = FastAPI(
  title=settings.APP_NAME,
  version=settings.APP_VERSION,
  debug=settings.DEBUG,
  lifespan=lifespan,
)

if settings.cors_origins:
  app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Platform-Bootstrap-Token"],
  )


@app.exception_handler(RedisError)
async def redis_error_handler(_request: Request, _error: RedisError) -> JSONResponse:
  return JSONResponse(
    status_code=503,
    content={"detail": "Temporary authentication storage is unavailable"},
  )

app.include_router(api_router)
