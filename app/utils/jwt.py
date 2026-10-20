import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
import jwt
from pydantic import SecretStr

from app.core.config import settings

JWT_ISSUER = "opspilot"
JWT_AUDIENCE = "opspilot-api"
JWT_ALGORITHM = "HS256"

def get_secret(secret: SecretStr | None, name: str) -> str:
  if secret is None:
    raise RuntimeError(f"{name} is not configured")
  value = secret.get_secret_value()
  if len(value.encode("utf-8")) < 32:
    raise RuntimeError(f"{name} must contain at least 32 bytes")
  return value

def encode_access_token(
  user_id: uuid.UUID | str,
  expires_at: datetime,
) -> str:
  now = datetime.now(timezone.utc)
  payload = {
    "sub": str(user_id),
    "type": "access",
    "jti": str(uuid.uuid4()),
    "iat": now,
    "exp": expires_at,
    "iss": JWT_ISSUER,
    "aud": JWT_AUDIENCE,
  }
  return jwt.encode(
    payload,
    get_secret(settings.JWT_ACCESS_SECRET_KEY, "JWT_ACCESS_SECRET_KEY"),
    algorithm=JWT_ALGORITHM,
  )

def verify_access_token(token: str) -> str:
  payload = jwt.decode(
    token,
    get_secret(settings.JWT_ACCESS_SECRET_KEY, "JWT_ACCESS_SECRET_KEY"),
    algorithms=[JWT_ALGORITHM],
    issuer=JWT_ISSUER,
    audience=JWT_AUDIENCE,
    options={"require": ["exp", "iat", "sub", "jti", "type", "iss", "aud"]},
  )
  if payload["type"] != "access" or not isinstance(payload["jti"], str):
    raise jwt.InvalidTokenError("Token is not an access token")
  return payload["sub"]

def create_access_token(user_id: uuid.UUID | str) -> str:
  expires_at = datetime.now(timezone.utc) + timedelta(
    minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
  )
  return encode_access_token(user_id, expires_at)


def validate_access_token_configuration() -> None:
  get_secret(settings.JWT_ACCESS_SECRET_KEY, "JWT_ACCESS_SECRET_KEY")


def validate_auth_token_configuration() -> None:
  get_secret(settings.JWT_ACCESS_SECRET_KEY, "JWT_ACCESS_SECRET_KEY")
  get_secret(settings.JWT_REFRESH_SECRET_KEY, "JWT_REFRESH_SECRET_KEY")
  secret = settings.OTP_HASH_SECRET_KEY
  if secret is None or len(secret.get_secret_value().encode("utf-8")) < 32:
    raise RuntimeError("OTP_HASH_SECRET_KEY must contain at least 32 bytes")


def create_refresh_token(user_id: uuid.UUID | str) -> str:
  now = datetime.now(timezone.utc)
  payload = {
    "sub": str(user_id),
    "type": "refresh",
    "jti": secrets.token_urlsafe(32),
    "iat": now,
    "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    "iss": JWT_ISSUER,
    "aud": JWT_AUDIENCE,
  }
  return jwt.encode(
    payload,
    get_secret(settings.JWT_REFRESH_SECRET_KEY, "JWT_REFRESH_SECRET_KEY"),
    algorithm=JWT_ALGORITHM,
  )

def decode_refresh_token(token: str) -> tuple[str, datetime]:
  payload = jwt.decode(
    token,
    get_secret(settings.JWT_REFRESH_SECRET_KEY, "JWT_REFRESH_SECRET_KEY"),
    algorithms=[JWT_ALGORITHM],
    issuer=JWT_ISSUER,
    audience=JWT_AUDIENCE,
    options={"require": ["exp", "iat", "sub", "jti", "type", "iss", "aud"]},
  )
  if (
    payload["type"] != "refresh"
    or not isinstance(payload["sub"], str)
    or not isinstance(payload["jti"], str)
  ):
    raise jwt.InvalidTokenError("Token is not a refresh token")
  expires = datetime.fromtimestamp(payload["exp"], timezone.utc)
  return payload["sub"], expires


def hash_refresh_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()
