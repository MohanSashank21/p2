import uuid
from datetime import datetime, timezone
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
import jwt

from app.core.exceptions import (
  EmailDeliveryError,
  InvalidCredentialsError,
  InvalidOTPError,
  OTPChallengeError,
  InvalidRefreshTokenError,
)
from app.core.config import settings
from app.db.auth import RefreshSession
from app.db.user import User
from app.schemas.auth_schema import (
  LoginRequest,
  OTPVerifyRequest,
  PasswordResetCompleteRequest,
  RegisterRequest,
)
from app.services.email_service import send_otp_email
from app.services.redis_service import (
  create_challenge,
  create_password_reset_grant,
  consume_password_reset_grant,
  activate_challenge_expiry,
  delete_challenge,
  limit_email_and_ip,
  resend_challenge as resend_redis_challenge,
  verify_challenge as verify_redis_challenge,
)
from app.utils.jwt import (
  create_refresh_token,
  decode_refresh_token,
  hash_refresh_token,
)
from app.utils.password import hash_password, verify_password

OTP_REQUEST_EMAIL_LIMIT = 3
OTP_REQUEST_IP_LIMIT = 15
OTP_RESEND_EMAIL_LIMIT = 3
OTP_RESEND_IP_LIMIT = 15
OTP_VERIFY_EMAIL_LIMIT = 10
OTP_VERIFY_IP_LIMIT = 30
LOGIN_EMAIL_LIMIT = 10
LOGIN_IP_LIMIT = 20
DUMMY_PASSWORD_HASH = hash_password("Dummy-Password-For-Timing-Consistency-8x!")

def _now() -> datetime:
  return datetime.now(timezone.utc)

def _utc(value: datetime) -> datetime:
  if value.tzinfo is None:
    return value.replace(tzinfo=timezone.utc)
  return value.astimezone(timezone.utc)

def normalize_email(email: str) -> str:
  return email.strip().lower()

async def _limit(
  redis: Redis,
  email: str,
  client_ip: str,
  action: str,
  email_limit: int,
  ip_limit: int,
) -> None:
  await limit_email_and_ip(
    redis,
    email,
    client_ip,
    action,
    email_limit,
    ip_limit,
  )

async def _send_new_challenge(
  redis: Redis,
  email: str,
  purpose: str,
  *,
  user_id: uuid.UUID | None = None,
  display_name: str | None = None,
  password_hash: str | None = None,
) -> None:
  normalized_email = normalize_email(email)
  challenge = await create_challenge(
    redis,
    normalized_email,
    purpose,
    user_id=str(user_id) if user_id else None,
    display_name=display_name,
    password_hash=password_hash,
  )
  if challenge is None:
    return
  code, challenge_id = challenge
  try:
    await send_otp_email(normalized_email, code)
  except EmailDeliveryError:
    await delete_challenge(redis, normalized_email, purpose)
    raise
  if not await activate_challenge_expiry(
    redis,
    normalized_email,
    purpose,
    challenge_id,
  ):
    raise OTPChallengeError(
      "Verification code expired before email delivery completed",
    )


async def start_registration(
  redis: Redis,
  session: AsyncSession,
  request: RegisterRequest,
  client_ip: str,
) -> None:
  email = normalize_email(str(request.email))
  await _limit(
    redis,
    email,
    client_ip,
    "otp_request",
    OTP_REQUEST_EMAIL_LIMIT,
    OTP_REQUEST_IP_LIMIT,
  )
  existing_user = await session.scalar(select(User.id).where(User.email == email))
  if existing_user is not None:
    return
  await _send_new_challenge(
    redis,
    email,
    "register",
    display_name=request.display_name,
    password_hash=hash_password(request.password),
  )


async def start_login(
  redis: Redis,
  session: AsyncSession,
  request: LoginRequest,
  client_ip: str,
) -> None:
  email = normalize_email(str(request.email))
  await _limit(redis, email, client_ip, "login", LOGIN_EMAIL_LIMIT, LOGIN_IP_LIMIT)
  user = await session.scalar(select(User).where(User.email == email))
  stored_hash = DUMMY_PASSWORD_HASH if user is None else user.password_hash
  password_matches = verify_password(request.password, stored_hash)
  if user is None or not user.email_verified or not password_matches:
    raise InvalidCredentialsError("Invalid email or password")

  await _limit(
    redis,
    email,
    client_ip,
    "otp_request",
    OTP_REQUEST_EMAIL_LIMIT,
    OTP_REQUEST_IP_LIMIT,
  )
  await _send_new_challenge(
    redis,
    email,
    "login",
    user_id=user.id,
  )


async def start_password_reset(
  redis: Redis,
  session: AsyncSession,
  email: str,
  client_ip: str,
) -> None:
  email = normalize_email(email)
  await _limit(
    redis,
    email,
    client_ip,
    "password_reset",
    OTP_REQUEST_EMAIL_LIMIT,
    OTP_REQUEST_IP_LIMIT,
  )
  user = await session.scalar(
    select(User).where(User.email == email, User.email_verified.is_(True)),
  )
  if user is None:
    return
  await _send_new_challenge(redis, email, "reset", user_id=user.id)


async def resend_challenge(
  redis: Redis,
  session: AsyncSession,
  email: str,
  purpose: str,
  client_ip: str,
) -> None:
  email = normalize_email(email)
  await _limit(
    redis,
    email,
    client_ip,
    "otp_resend",
    OTP_RESEND_EMAIL_LIMIT,
    OTP_RESEND_IP_LIMIT,
  )
  challenge = await resend_redis_challenge(redis, email, purpose)
  if challenge is None:
    return
  code, state = challenge
  if purpose in {"login", "reset"}:
    try:
      user_id = uuid.UUID(state.get("user_id", ""))
    except ValueError:
      await delete_challenge(redis, email, purpose)
      return
    user = await session.get(User, user_id)
    if user is None or not user.email_verified:
      await delete_challenge(redis, email, purpose)
      return
  try:
    await send_otp_email(email, code)
  except EmailDeliveryError:
    await delete_challenge(redis, email, purpose)
    raise
  if not await activate_challenge_expiry(
    redis,
    email,
    purpose,
    state["challenge_id"],
  ):
    raise OTPChallengeError(
      "Verification code expired before email delivery completed",
    )


async def _verify_challenge(
  redis: Redis,
  session: AsyncSession,
  request: OTPVerifyRequest,
  purpose: str,
  client_ip: str,
) -> tuple[User, dict[str, str]]:
  email = normalize_email(str(request.email))
  await _limit(
    redis,
    email,
    client_ip,
    "otp_verify",
    OTP_VERIFY_EMAIL_LIMIT,
    OTP_VERIFY_IP_LIMIT,
  )
  state = await verify_redis_challenge(
    redis,
    email,
    purpose,
    request.code,
  )
  if state is None:
    raise InvalidOTPError("Invalid or expired verification code")

  try:
    user_id = uuid.UUID(state["user_id"]) if state["user_id"] else None
  except ValueError:
    raise InvalidOTPError("Invalid or expired verification code") from None

  if purpose == "register":
    display_name = state["display_name"]
    pending_password_hash = state["password_hash"]
    if not display_name or not pending_password_hash:
      raise InvalidOTPError("Invalid or expired verification code")
    user = User(
      email=email,
      display_name=display_name,
      password_hash=pending_password_hash,
      email_verified=True,
    )
    session.add(user)
    try:
      await session.commit()
    except IntegrityError:
      await session.rollback()
      raise InvalidOTPError("Invalid or expired verification code") from None
    return user, state

  user = await session.get(User, user_id) if user_id else None
  if user is None or not user.email_verified:
    raise InvalidOTPError("Invalid or expired verification code")
  return user, state


async def verify_challenge(
  redis: Redis,
  session: AsyncSession,
  request: OTPVerifyRequest,
  purpose: str,
  client_ip: str,
) -> User:
  user, _ = await _verify_challenge(redis, session, request, purpose, client_ip)
  return user


async def reset_password(
  redis: Redis,
  session: AsyncSession,
  request: PasswordResetCompleteRequest,
) -> None:
  user_id = await consume_password_reset_grant(redis, request.reset_token)
  try:
    parsed_user_id = uuid.UUID(user_id) if user_id else None
  except ValueError:
    raise InvalidOTPError("Invalid or expired password reset authorization") from None
  user = await session.get(User, parsed_user_id) if parsed_user_id else None
  if user is None or not user.email_verified:
    raise InvalidOTPError("Invalid or expired password reset authorization")
  user.password_hash = hash_password(request.new_password)
  await session.execute(
    update(RefreshSession)
    .where(
      RefreshSession.user_id == user.id,
      RefreshSession.revoked_at.is_(None),
    )
    .values(revoked_at=_now()),
  )
  await session.commit()


async def verify_password_reset(
  redis: Redis,
  session: AsyncSession,
  request: OTPVerifyRequest,
  client_ip: str,
) -> tuple[str, int]:
  user = await verify_challenge(redis, session, request, "reset", client_ip)
  grant = await create_password_reset_grant(redis, str(user.id))
  return grant, settings.OTP_EXPIRE_MINUTES * 60


async def change_password(
  session: AsyncSession,
  user: User,
  current_password: str,
  new_password: str,
) -> None:
  if not verify_password(current_password, user.password_hash):
    raise InvalidCredentialsError("Current password is incorrect")
  user.password_hash = hash_password(new_password)
  await session.execute(
    update(RefreshSession)
    .where(
      RefreshSession.user_id == user.id,
      RefreshSession.revoked_at.is_(None),
    )
    .values(revoked_at=_now()),
  )
  await session.commit()


async def create_refresh_session(
  session: AsyncSession,
  user_id: uuid.UUID,
  family_id: uuid.UUID | None = None,
) -> tuple[RefreshSession, str]:
  raw_token = create_refresh_token(user_id)
  _, expires_at = decode_refresh_token(raw_token)
  refresh_session = RefreshSession(
    family_id=family_id or uuid.uuid4(),
    user_id=user_id,
    token_hash=hash_refresh_token(raw_token),
    expires_at=expires_at,
  )
  session.add(refresh_session)
  await session.commit()
  return refresh_session, raw_token


async def rotate_refresh_session(
  session: AsyncSession,
  raw_token: str,
) -> tuple[User, RefreshSession, str]:
  try:
    subject, _ = decode_refresh_token(raw_token)
    user_id = uuid.UUID(subject)
  except (ValueError, RuntimeError, jwt.InvalidTokenError) as error:
    raise InvalidRefreshTokenError("Refresh session is invalid or expired") from error

  token_hash = hash_refresh_token(raw_token)
  now = _now()
  claimed = await session.execute(
    update(RefreshSession)
    .where(
      RefreshSession.token_hash == token_hash,
      RefreshSession.revoked_at.is_(None),
      RefreshSession.expires_at > now,
      RefreshSession.user_id == user_id,
    )
    .values(revoked_at=now)
    .returning(
      RefreshSession.id,
      RefreshSession.family_id,
      RefreshSession.user_id,
    ),
  )
  claimed_rows = claimed.fetchall()
  claimed.close()
  claimed_row = claimed_rows[0] if claimed_rows else None
  if claimed_row is None:
    existing = await session.scalar(
      select(RefreshSession).where(RefreshSession.token_hash == token_hash),
    )
    if existing is None or existing.user_id != user_id:
      raise InvalidRefreshTokenError("Refresh session is invalid or expired")
    if existing.revoked_at is not None:
      await session.execute(
        update(RefreshSession)
        .where(
          RefreshSession.family_id == existing.family_id,
          RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now),
      )
    else:
      existing.revoked_at = now
    await session.commit()
    raise InvalidRefreshTokenError("Refresh session is invalid or expired")

  current_id, family_id, current_user_id = claimed_row
  current = await session.get(RefreshSession, current_id)
  if current is None:
    raise RuntimeError("Refresh session disappeared during rotation")
  user = await session.get(User, current_user_id)
  if user is None or not user.email_verified:
    await session.commit()
    raise InvalidRefreshTokenError("Refresh session is invalid or expired")

  replacement_token = create_refresh_token(current_user_id)
  _, expires_at = decode_refresh_token(replacement_token)
  replacement = RefreshSession(
    family_id=family_id,
    user_id=current_user_id,
    token_hash=hash_refresh_token(replacement_token),
    expires_at=expires_at,
  )
  session.add(replacement)
  await session.flush()
  current.replaced_by_id = replacement.id
  await session.commit()
  return user, replacement, replacement_token


async def revoke_refresh_session(
  session: AsyncSession,
  raw_token: str | None,
) -> None:
  if not raw_token:
    return
  refresh_session = await session.scalar(
    select(RefreshSession).where(
      RefreshSession.token_hash == hash_refresh_token(raw_token),
    ),
  )
  if refresh_session is not None and refresh_session.revoked_at is None:
    refresh_session.revoked_at = _now()
    await session.commit()
