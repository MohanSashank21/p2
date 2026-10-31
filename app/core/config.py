from typing import Literal
from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
  APP_NAME: str = "OpsPilot AI"
  APP_VERSION: str = "1.0.0"
  DEBUG: bool = False
  DATABASE_URL: str
  REDIS_URL: str = "redis://localhost:6379"
  JWT_ACCESS_SECRET_KEY: SecretStr | None = None
  JWT_REFRESH_SECRET_KEY: SecretStr | None = None
  OTP_HASH_SECRET_KEY: SecretStr | None = None
  LOKI_CREDENTIAL_ENCRYPTION_KEY: SecretStr | None = None
  LOKI_ALLOWED_HOSTS: str = ""
  LOKI_QUERY_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=60)
  PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY: SecretStr | None = None
  PROMETHEUS_ALLOWED_HOSTS: str = ""
  PROMETHEUS_QUERY_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=60)
  TRACE_CREDENTIAL_ENCRYPTION_KEY: SecretStr | None = None
  TRACE_ALLOWED_HOSTS: str = ""
  TRACE_QUERY_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=60)
  DOCKER_HOST: str | None = None
  DOCKER_QUERY_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=30)
  DOCKER_LOG_MAX_BYTES: int = Field(default=131072, ge=1024, le=524288)
  GITHUB_APP_ID: str | None = None
  GITHUB_APP_SLUG: str | None = None
  GITHUB_APP_PRIVATE_KEY: SecretStr | None = None
  GITHUB_WEBHOOK_SECRET: SecretStr | None = None
  GITHUB_API_URL: str = "https://api.github.com"
  GITHUB_API_TIMEOUT_SECONDS: int = Field(default=15, ge=1, le=60)
  ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=60)
  REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)
  OTP_EXPIRE_MINUTES: int = Field(default=5, ge=1, le=30)
  OTP_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=10)
  OTP_MAX_RESENDS: int = Field(default=3, ge=0, le=5)
  SMTP_HOST: str | None = None
  SMTP_PORT: int = Field(default=587, ge=1, le=65535)
  SMTP_USER: str | None = Field(
    default=None,
    validation_alias=AliasChoices("SMTP_USERNAME", "SMTP_USER"),
  )
  SMTP_PASSWORD: SecretStr | None = None
  SMTP_FROM: str | None = None
  SMTP_USE_SSL: bool = False
  SMTP_USE_STARTTLS: bool = True
  SMTP_TIMEOUT_SECONDS: int = Field(default=10, ge=1, le=60)
  REFRESH_COOKIE_SECURE: bool = True
  REFRESH_COOKIE_SAMESITE: Literal["strict", "lax", "none"] = "strict"
  FRONTEND_ORIGINS: str = ""
  FRONTEND_BASE_URL: str = "http://localhost:5173"

  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    extra="ignore",
  )

  @property
  def cors_origins(self) -> list[str]:
    return [origin.strip() for origin in self.FRONTEND_ORIGINS.split(",") if origin.strip()]

settings = Settings()