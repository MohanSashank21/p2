import uuid,jwt
from datetime import datetime, timedelta, timezone
from pydantic import SecretStr
from app.core.config import settings

def _get_secret(secret: SecretStr | None, name: str) -> str:
  if secret is None:
    raise RuntimeError(f"{name} is not configured")
  return secret.get_secret_value()

def _create_token(
  user_id: uuid.UUID | str,
  token_type: str,
  secret: SecretStr | None,
  expires_at: datetime,
) -> str:
  payload = {
    "sub": str(user_id),
    "type": token_type,
    "iat": datetime.now(timezone.utc),
    "exp": expires_at,
  }
  return jwt.encode(
    payload,
    _get_secret(secret, f"JWT_{token_type.upper()}_SECRET_KEY"),
    algorithm="HS256",
  )

def _verify_token(
  token: str,
  token_type: str,
  secret: SecretStr | None,
) -> str:
  payload = jwt.decode(
    token,
    _get_secret(secret, f"JWT_{token_type.upper()}_SECRET_KEY"),
    algorithms=["HS256"],
    options={"require": ["exp", "iat", "sub", "type"]},
  )
  if payload["type"] != token_type:
    raise jwt.InvalidTokenError(f"Token is not a {token_type} token")

  return payload["sub"]

def create_access_token(user_id: uuid.UUID | str) -> str:
  expires_at = datetime.now(timezone.utc) + timedelta(
    minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
  )
  return _create_token(
    user_id,
    "access",
    settings.JWT_ACCESS_SECRET_KEY,
    expires_at,
  )

def verify_access_token(token: str) -> str:
  return _verify_token(token, "access", settings.JWT_ACCESS_SECRET_KEY)

def create_refresh_token(user_id: uuid.UUID | str) -> str:
  expires_at = datetime.now(timezone.utc) + timedelta(
    days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
  )
  return _create_token(
    user_id,
    "refresh",
    settings.JWT_REFRESH_SECRET_KEY,
    expires_at,
  )

def verify_refresh_token(token: str) -> str:
  return _verify_token(token, "refresh", settings.JWT_REFRESH_SECRET_KEY)
