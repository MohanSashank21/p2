from fastapi import HTTPException, Request, status
from redis.asyncio import Redis


async def get_redis(request: Request) -> Redis:
  client = getattr(request.app.state, "redis", None)
  if client is None:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="Temporary authentication storage is unavailable",
    )
  return client
