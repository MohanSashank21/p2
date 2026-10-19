from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.exceptions import (
  EmailDeliveryError,
  InvalidCredentialsError,
  InvalidOTPError,
  InvalidRefreshTokenError,
  RateLimitExceededError,
)
from app.db.auth import RefreshSession
from app.db.database import get_db
from app.db.redis import get_redis
from app.db.membership import Membership
from app.db.organisation import Organisation
from app.db.user import User
from app.schemas.auth_schema import (
  LoginRequest,
  OTPChallengeResponse,
  OTPRequest,
  OTPResendRequest,
  OTPVerifyRequest,
  RegisterRequest,
  CurrentUserResponse,
  TokenResponse,
  PasswordChangeRequest,
  PasswordResetCompleteRequest,
  PasswordResetVerifiedResponse,
)
from app.services.auth_service import (
  change_password,
  create_refresh_session,
  resend_challenge,
  reset_password,
  revoke_refresh_session,
  rotate_refresh_session,
  start_password_reset,
  start_login,
  start_registration,
  verify_challenge,
  verify_password_reset as verify_password_reset_otp,
)
from app.utils.jwt import create_access_token, validate_auth_token_configuration
router = APIRouter(prefix="/auth", tags=["auth"])
REFRESH_COOKIE_NAME = "opspilot_refresh"
REFRESH_COOKIE_PATH = "/auth"
OTP_RESPONSE_MESSAGE = (
  "If your request is eligible, a verification code has been sent to you by email."
)

def _set_refresh_cookie(
  response: Response,
  refresh_session: RefreshSession,
  token: str,
) -> None:
  expires_at = refresh_session.expires_at
  if expires_at.tzinfo is None:
    expires_at = expires_at.replace(tzinfo=timezone.utc)
  max_age = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
  response.set_cookie(
    key=REFRESH_COOKIE_NAME,
    value=token,
    max_age=max_age,
    httponly=True,
    secure=settings.REFRESH_COOKIE_SECURE,
    samesite=settings.REFRESH_COOKIE_SAMESITE,
    path=REFRESH_COOKIE_PATH,
  )

def _clear_refresh_cookie(response: Response) -> None:
  response.delete_cookie(
    key=REFRESH_COOKIE_NAME,
    httponly=True,
    secure=settings.REFRESH_COOKIE_SECURE,
    samesite=settings.REFRESH_COOKIE_SAMESITE,
    path=REFRESH_COOKIE_PATH,
  )


def _validate_cookie_request_origin(request: Request) -> None:
  origin = request.headers.get("origin")
  same_origin = f"{request.url.scheme}://{request.url.netloc}"
  if (
    origin is not None
    and origin != same_origin
    and origin not in settings.cors_origins
  ):
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail="Request origin is not allowed",
    )


def _raise_rate_limit(error: RateLimitExceededError) -> HTTPException:
  return HTTPException(
    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
    detail=str(error),
    headers={"Retry-After": "600"},
  )


def _raise_email_delivery(error: EmailDeliveryError) -> HTTPException:
  return HTTPException(
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    detail="Email could not be delivered. Please try again later.",
  )


def _raise_missing_auth_config(error: RuntimeError) -> HTTPException:
  return HTTPException(
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    detail="Authentication or email delivery is not configured.",
  )


async def _complete_authentication(
  response: Response,
  session: AsyncSession,
  user: User,
) -> TokenResponse:
  try:
    validate_auth_token_configuration()
    access_token = create_access_token(user.id)
    refresh_session, raw_refresh_token = await create_refresh_session(
      session,
      user.id,
    )
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  _set_refresh_cookie(response, refresh_session, raw_refresh_token)
  return TokenResponse(
    access_token=access_token,
    expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
  )


@router.post(
  "/register",
  response_model=OTPChallengeResponse,
  status_code=status.HTTP_202_ACCEPTED,
)
async def register(
  request: RegisterRequest,
  http_request: Request,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> OTPChallengeResponse:
  try:
    await start_registration(
      redis,
      session,
      request,
      http_request.client.host if http_request.client else "",
    )
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except EmailDeliveryError as error:
    raise _raise_email_delivery(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  return OTPChallengeResponse(message=OTP_RESPONSE_MESSAGE)


@router.post(
  "/register/verify",
  response_model=TokenResponse,
)
async def verify_registration(
  request: OTPVerifyRequest,
  http_request: Request,
  response: Response,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> TokenResponse:
  try:
    user = await verify_challenge(
      redis,
      session,
      request,
      "register",
      http_request.client.host if http_request.client else "",
    )
    return await _complete_authentication(response, session, user)
  except InvalidOTPError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error


@router.post(
  "/login",
  response_model=OTPChallengeResponse,
  status_code=status.HTTP_202_ACCEPTED,
)
async def login(
  request: LoginRequest,
  http_request: Request,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> OTPChallengeResponse:
  try:
    await start_login(
      redis,
      session,
      request,
      http_request.client.host if http_request.client else "",
    )
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except EmailDeliveryError as error:
    raise _raise_email_delivery(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  return OTPChallengeResponse(message=OTP_RESPONSE_MESSAGE)


@router.post("/login/verify", response_model=TokenResponse)
async def verify_login(
  request: OTPVerifyRequest,
  http_request: Request,
  response: Response,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> TokenResponse:
  try:
    user = await verify_challenge(
      redis,
      session,
      request,
      "login",
      http_request.client.host if http_request.client else "",
    )
    return await _complete_authentication(response, session, user)
  except InvalidOTPError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error


@router.post(
  "/otp/resend",
  response_model=OTPChallengeResponse,
  status_code=status.HTTP_202_ACCEPTED,
  responses={
    status.HTTP_422_UNPROCESSABLE_CONTENT: {
      "description": "Invalid email or unsupported resend purpose.",
    },
    status.HTTP_429_TOO_MANY_REQUESTS: {
      "description": "OTP resend limit reached.",
    },
    status.HTTP_503_SERVICE_UNAVAILABLE: {
      "description": "Email delivery or required authentication service is unavailable.",
    },
  },
)
async def resend_otp(
  request: OTPResendRequest,
  http_request: Request,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> OTPChallengeResponse:
  try:
    await resend_challenge(
      redis,
      session,
      str(request.email),
      request.purpose,
      http_request.client.host if http_request.client else "",
    )
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except EmailDeliveryError as error:
    raise _raise_email_delivery(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  return OTPChallengeResponse(message=OTP_RESPONSE_MESSAGE)


@router.post(
  "/password/reset",
  response_model=OTPChallengeResponse,
  status_code=status.HTTP_202_ACCEPTED,
)
async def request_password_reset(
  request: OTPRequest,
  http_request: Request,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> OTPChallengeResponse:
  try:
    await start_password_reset(
      redis,
      session,
      str(request.email),
      http_request.client.host if http_request.client else "",
    )
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  except EmailDeliveryError as error:
    raise _raise_email_delivery(error) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  return OTPChallengeResponse(message=OTP_RESPONSE_MESSAGE)


@router.post(
  "/password/reset/verify",
  response_model=PasswordResetVerifiedResponse,
)
async def verify_password_reset(
  request: OTPVerifyRequest,
  http_request: Request,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> PasswordResetVerifiedResponse:
  try:
    reset_token, expires_in = await verify_password_reset_otp(
      redis,
      session,
      request,
      http_request.client.host if http_request.client else "",
    )
  except InvalidOTPError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  except RateLimitExceededError as error:
    raise _raise_rate_limit(error) from error
  return PasswordResetVerifiedResponse(
    reset_token=reset_token,
    expires_in=expires_in,
  )


@router.post(
  "/password/reset/complete",
  status_code=status.HTTP_204_NO_CONTENT,
)
async def complete_password_reset(
  request: PasswordResetCompleteRequest,
  redis: Redis = Depends(get_redis),
  session: AsyncSession = Depends(get_db),
) -> Response:
  try:
    await reset_password(redis, session, request)
  except InvalidOTPError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_current_password(
  request: PasswordChangeRequest,
  response: Response,
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> Response:
  try:
    await change_password(
      session,
      user,
      request.current_password,
      request.new_password,
    )
  except InvalidCredentialsError as error:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail=str(error),
    ) from error
  _clear_refresh_cookie(response)
  response.status_code = status.HTTP_204_NO_CONTENT
  return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
  request: Request,
  response: Response,
  session: AsyncSession = Depends(get_db),
) -> TokenResponse:
  _validate_cookie_request_origin(request)
  raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
  try:
    validate_auth_token_configuration()
    if not raw_token:
      raise InvalidRefreshTokenError("Refresh session is invalid or expired")
    user, refresh_session, replacement_token = await rotate_refresh_session(
      session,
      raw_token,
    )
    access_token = create_access_token(user.id)
  except InvalidRefreshTokenError as error:
    _clear_refresh_cookie(response)
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Refresh session is invalid or expired",
    ) from error
  except RuntimeError as error:
    raise _raise_missing_auth_config(error) from error
  _set_refresh_cookie(response, refresh_session, replacement_token)
  return TokenResponse(
    access_token=access_token,
    expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
  )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
  request: Request,
  response: Response,
  session: AsyncSession = Depends(get_db),
) -> Response:
  _validate_cookie_request_origin(request)
  await revoke_refresh_session(
    session,
    request.cookies.get(REFRESH_COOKIE_NAME),
  )
  _clear_refresh_cookie(response)
  response.status_code = status.HTTP_204_NO_CONTENT
  return response


@router.get("/me", response_model=CurrentUserResponse)
async def get_me(
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
) -> CurrentUserResponse:
  memberships = await session.execute(
    select(Membership, Organisation)
    .join(Organisation, Membership.organisation_id == Organisation.id)
    .where(Membership.user_id == user.id)
    .order_by(Organisation.name)
  )
  return CurrentUserResponse(
    id=user.id,
    email=user.email,
    display_name=user.display_name,
    email_verified=user.email_verified,
    organisations=[
      {
        "id": membership.organisation_id,
        "name": organisation.name,
        "role": membership.role,
      }
      for membership, organisation in memberships
    ],
  )
