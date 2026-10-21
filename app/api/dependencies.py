import uuid
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.user import User
from app.utils.jwt import verify_access_token

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
  credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
  session: AsyncSession = Depends(get_db),
) -> User:
  if credentials is None or credentials.scheme.lower() != "bearer":
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Authentication required",
      headers={"WWW-Authenticate": "Bearer"},
    )
  try:
    user_id = uuid.UUID(verify_access_token(credentials.credentials))
  except RuntimeError as error:
    raise HTTPException(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      detail="Authentication is not configured.",
    ) from error
  except (ValueError, jwt.InvalidTokenError) as error:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Invalid or expired access token",
      headers={"WWW-Authenticate": "Bearer"},
    ) from error

  user = await session.scalar(
    select(User).where(
      User.id == user_id,
      User.email_verified.is_(True),
    ),
  )
  if user is None:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Invalid or expired access token",
      headers={"WWW-Authenticate": "Bearer"},
    )
  return user
