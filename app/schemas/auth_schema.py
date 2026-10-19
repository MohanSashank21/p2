import uuid
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


def _validate_password(password: str) -> str:
  if not any(character.isupper() for character in password):
    raise ValueError("Password must contain an uppercase letter")
  if not any(character.islower() for character in password):
    raise ValueError("Password must contain a lowercase letter")
  if not any(character.isdigit() for character in password):
    raise ValueError("Password must contain a number")
  if not any(
    not character.isalnum() and not character.isspace()
    for character in password
  ):
    raise ValueError("Password must contain a special character")
  return password


class RegisterRequest(BaseModel):
  email: EmailStr
  display_name: str = Field(min_length=1, max_length=120)
  password: str = Field(min_length=8, max_length=128)

  @field_validator("display_name")
  @classmethod
  def validate_display_name(cls, display_name: str) -> str:
    display_name = display_name.strip()
    if not display_name:
      raise ValueError("Display name cannot be blank")
    return display_name

  @field_validator("password")
  @classmethod
  def validate_password(cls, password: str) -> str:
    return _validate_password(password)


class OTPRequest(BaseModel):
  email: EmailStr


class LoginRequest(OTPRequest):
  password: str = Field(min_length=8, max_length=128)


class OTPVerifyRequest(OTPRequest):
  code: str = Field(pattern=r"^\d{6}$")


class OTPResendRequest(OTPRequest):
  purpose: Literal["register", "login", "reset"]

  @field_validator("purpose", mode="before")
  @classmethod
  def normalize_purpose(cls, purpose: str) -> str:
    aliases = {
      "registration": "register",
      "password_reset": "reset",
      "password-reset": "reset",
      "forgot_password": "reset",
      "forgot-password": "reset",
    }
    if isinstance(purpose, str):
      return aliases.get(purpose.strip().casefold(), purpose.strip().casefold())
    return purpose


class PasswordResetCompleteRequest(BaseModel):
  reset_token: str = Field(min_length=32, max_length=200)
  new_password: str = Field(min_length=8, max_length=128)

  @field_validator("new_password")
  @classmethod
  def validate_new_password(cls, password: str) -> str:
    return _validate_password(password)


class PasswordResetVerifiedResponse(BaseModel):
  reset_token: str
  expires_in: int


class PasswordChangeRequest(BaseModel):
  current_password: str = Field(min_length=1, max_length=128)
  new_password: str = Field(min_length=8, max_length=128)

  @field_validator("new_password")
  @classmethod
  def validate_new_password(cls, password: str) -> str:
    return _validate_password(password)


class OTPChallengeResponse(BaseModel):
  message: str


class TokenResponse(BaseModel):
  access_token: str
  token_type: Literal["bearer"] = "bearer"
  expires_in: int


class UserResponse(BaseModel):
  id: uuid.UUID
  email: EmailStr
  display_name: str
  email_verified: bool


class OrganisationMembershipResponse(BaseModel):
  id: uuid.UUID
  name: str
  role: Literal["owner", "admin", "worker"]


class CurrentUserResponse(UserResponse):
  organisations: list[OrganisationMembershipResponse]


class OrganisationBootstrapRequest(BaseModel):
  name: str = Field(min_length=1, max_length=120)

  @field_validator("name")
  @classmethod
  def validate_name(cls, name: str) -> str:
    name = name.strip()
    if not name:
      raise ValueError("Organisation name cannot be blank")
    return name


class OrganisationBootstrapResponse(BaseModel):
  organisation_id: uuid.UUID
  name: str
  role: Literal["owner"] = "owner"


class OrganisationInvitationRequest(BaseModel):
  email: EmailStr
  role: Literal["admin", "worker"]


class OrganisationInvitationResponse(BaseModel):
  message: str
  expires_in: int


class OrganisationInvitationAcceptRequest(BaseModel):
  token: str = Field(min_length=32, max_length=200)
