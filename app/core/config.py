from pydantic_settings import BaseSettings,SettingsConfigDict

class Settings(BaseSettings):
  APP_NAME:str = "OpsPilot AI"
  APP_VERSION:str = "1.0.0"
  DEBUG:bool = True
  MONGO_URI:str
  DATABASE_NAME:str
  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    extra="ignore"
  )

settings = Settings()