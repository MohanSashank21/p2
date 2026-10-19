from fastapi import APIRouter, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.db.database import check_database_connection

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check():
  return {"status":"healthy"}


@router.get("/health/ready")
async def readiness_check(request: Request, response: Response) -> dict[str, bool]:
  postgres_ready = False
  redis_ready = False
  try:
    postgres_ready = await check_database_connection()
  except SQLAlchemyError:
    pass
  redis_client = getattr(request.app.state, "redis", None)
  if redis_client is not None:
    try:
      redis_ready = bool(await redis_client.ping())
    except RedisError:
      redis_ready = False
  ready = postgres_ready and redis_ready
  if not ready:
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
  return {"ready": ready, "postgres": postgres_ready, "redis": redis_ready}
