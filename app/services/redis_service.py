import hashlib
import hmac
import secrets
from collections.abc import Mapping
from typing import Any

from redis.asyncio import Redis

from app.core.config import settings
from app.core.exceptions import RateLimitExceededError

_INCREMENT_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""

_CREATE_CHALLENGE = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1],
  'purpose', ARGV[1],
  'challenge_id', ARGV[2],
  'code_hash', ARGV[3],
  'attempts', 0,
  'resend_count', 0,
  'user_id', ARGV[4],
  'display_name', ARGV[5],
  'password_hash', ARGV[6])
redis.call('EXPIRE', KEYS[1], ARGV[7])
return 1
"""

_RESEND_CHALLENGE = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
if redis.call('HGET', KEYS[1], 'challenge_id') ~= ARGV[1] then
  return 0
end
if redis.call('HGET', KEYS[1], 'code_hash') ~= ARGV[2] then
  return 0
end
local resend_count = tonumber(redis.call('HGET', KEYS[1], 'resend_count') or '0')
if resend_count >= tonumber(ARGV[4]) then
  return -1
end
redis.call('HSET', KEYS[1],
  'code_hash', ARGV[3],
  'attempts', 0,
  'resend_count', resend_count + 1)
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""

_VERIFY_CHALLENGE = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'missing'}
end
if redis.call('HGET', KEYS[1], 'purpose') ~= ARGV[1] then
  return {'missing'}
end
if redis.call('HGET', KEYS[1], 'challenge_id') ~= ARGV[2] then
  return {'missing'}
end
local stored_hash = redis.call('HGET', KEYS[1], 'code_hash')
if stored_hash ~= ARGV[3] then
  local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
  if attempts >= tonumber(ARGV[4]) then
    redis.call('DEL', KEYS[1])
  end
  return {'invalid'}
end
local result = {
  'valid',
  redis.call('HGET', KEYS[1], 'challenge_id') or '',
  redis.call('HGET', KEYS[1], 'user_id') or '',
  redis.call('HGET', KEYS[1], 'display_name') or '',
  redis.call('HGET', KEYS[1], 'password_hash') or ''
}
redis.call('DEL', KEYS[1])
return result
"""

_CONSUME_PASSWORD_RESET_GRANT = """
local user_id = redis.call('GET', KEYS[1])
if not user_id then
  return nil
end
redis.call('DEL', KEYS[1])
return user_id
"""


def _key(scope: str, subject: str) -> str:
  secret = settings.OTP_HASH_SECRET_KEY
  if secret is None or len(secret.get_secret_value().encode("utf-8")) < 32:
    raise RuntimeError("OTP_HASH_SECRET_KEY must contain at least 32 bytes")
  digest = hmac.new(
    secret.get_secret_value().encode("utf-8"),
    f"{scope}:{subject}".encode("utf-8"),
    hashlib.sha256,
  ).hexdigest()
  return f"opspilot:{scope}:{digest}"


def _normalize_email(email: str) -> str:
  return email.strip().casefold()


def _hash_otp(email: str, purpose: str, challenge_id: str, code: str) -> str:
  secret = settings.OTP_HASH_SECRET_KEY
  if secret is None or len(secret.get_secret_value().encode("utf-8")) < 32:
    raise RuntimeError("OTP_HASH_SECRET_KEY must contain at least 32 bytes")
  payload = f"{_normalize_email(email)}:{purpose}:{challenge_id}:{code}".encode("utf-8")
  return hmac.new(secret.get_secret_value().encode("utf-8"), payload, hashlib.sha256).hexdigest()


async def bump_rate_limit(
  client: Redis,
  scope: str,
  subject: str,
  limit: int,
  window_seconds: int,
) -> None:
  key = _key(f"rate:{scope}", subject)
  count = int(await client.eval(_INCREMENT_WITH_TTL, 1, key, window_seconds))
  if count > limit:
    raise RateLimitExceededError("Too many requests. Please try again later.")


async def limit_email_and_ip(
  client: Redis,
  email: str,
  client_ip: str,
  action: str,
  email_limit: int,
  ip_limit: int,
  window_seconds: int = 600,
) -> None:
  await bump_rate_limit(client, f"{action}:email", _normalize_email(email), email_limit, window_seconds)
  if client_ip:
    await bump_rate_limit(client, f"{action}:ip", client_ip, ip_limit, window_seconds)


async def create_challenge(
  client: Redis,
  email: str,
  purpose: str,
  *,
  user_id: str | None = None,
  display_name: str | None = None,
  password_hash: str | None = None,
) -> str | None:
  normalized_email = _normalize_email(email)
  key = _key(f"otp:{purpose}", normalized_email)
  challenge_id = secrets.token_urlsafe(24)
  code = f"{secrets.randbelow(1_000_000):06d}"
  code_hash = _hash_otp(normalized_email, purpose, challenge_id, code)
  ttl = settings.OTP_EXPIRE_MINUTES * 60
  created = int(
    await client.eval(
      _CREATE_CHALLENGE,
      1,
      key,
      purpose,
      challenge_id,
      code_hash,
      user_id or "",
      display_name or "",
      password_hash or "",
      ttl,
    )
  )
  return code if created else None


async def resend_challenge(
  client: Redis,
  email: str,
  purpose: str,
) -> tuple[str, Mapping[str, str]] | None:
  normalized_email = _normalize_email(email)
  key = _key(f"otp:{purpose}", normalized_email)
  state: dict[str, Any] = await client.hgetall(key)
  challenge_id = state.get("challenge_id")
  if not challenge_id or state.get("purpose") != purpose:
    return None
  code = f"{secrets.randbelow(1_000_000):06d}"
  code_hash = _hash_otp(normalized_email, purpose, challenge_id, code)
  result = int(
    await client.eval(
      _RESEND_CHALLENGE,
      1,
      key,
      challenge_id,
      state.get("code_hash", ""),
      code_hash,
      settings.OTP_MAX_RESENDS,
      settings.OTP_EXPIRE_MINUTES * 60,
    )
  )
  if result == -1:
    raise RateLimitExceededError("OTP resend limit reached")
  if result == 0:
    return None
  return code, state


async def verify_challenge(
  client: Redis,
  email: str,
  purpose: str,
  code: str,
) -> dict[str, str] | None:
  normalized_email = _normalize_email(email)
  key = _key(f"otp:{purpose}", normalized_email)
  state: dict[str, Any] = await client.hgetall(key)
  challenge_id = state.get("challenge_id")
  if not challenge_id:
    return None
  code_hash = _hash_otp(normalized_email, purpose, challenge_id, code)
  result = await client.eval(
    _VERIFY_CHALLENGE,
    1,
    key,
    purpose,
    challenge_id,
    code_hash,
    settings.OTP_MAX_ATTEMPTS,
  )
  if not result or result[0] != b"valid" and result[0] != "valid":
    return None
  return {
    "challenge_id": result[1].decode() if isinstance(result[1], bytes) else result[1],
    "user_id": result[2].decode() if isinstance(result[2], bytes) else result[2],
    "display_name": result[3].decode() if isinstance(result[3], bytes) else result[3],
    "password_hash": result[4].decode() if isinstance(result[4], bytes) else result[4],
  }


async def delete_challenge(client: Redis, email: str, purpose: str) -> None:
  await client.delete(_key(f"otp:{purpose}", _normalize_email(email)))


async def create_password_reset_grant(client: Redis, user_id: str) -> str:
  grant = secrets.token_urlsafe(32)
  ttl = settings.OTP_EXPIRE_MINUTES * 60
  created = await client.set(
    _key("password-reset-grant", grant),
    user_id,
    ex=ttl,
    nx=True,
  )
  if not created:
    raise RuntimeError("Could not create password reset grant")
  return grant


async def consume_password_reset_grant(
  client: Redis,
  grant: str,
) -> str | None:
  return await client.eval(
    _CONSUME_PASSWORD_RESET_GRANT,
    1,
    _key("password-reset-grant", grant),
  )
