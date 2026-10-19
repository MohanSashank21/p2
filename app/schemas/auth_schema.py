from typing import Literal
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
  email: EmailStr
  display_name: str = Field(min_length=1, max_length=120)
  password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
  email: EmailStr
  password: str = Field(min_length=1, max_length=128)

class TokenResponse(BaseModel):
  access_token: str
  refresh_token: str
  token_type: Literal["bearer"] = "bearer"
  expires_in: int
