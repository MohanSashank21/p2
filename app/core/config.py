from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  APP_NAME: str = "OpsPilot AI"
  APP_VERSION: str = "1.0.0"
  DEBUG: bool = True
  DATABASE_URL: str
  JWT_ACCESS_SECRET_KEY: SecretStr | None = None
  JWT_REFRESH_SECRET_KEY: SecretStr | None = None
  ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
  REFRESH_TOKEN_EXPIRE_DAYS: int = 7

  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    extra="ignore"
  )


settings = Settings()