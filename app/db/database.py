from app.core.config import settings
from sqlalchemy.ext.asyncio import (create_async_engine,async_sessionmaker)
from sqlalchemy import text

engine = create_async_engine(
  settings.DATABASE_URL,
  pool_pre_ping=True
)

AsyncSessionLocal = async_sessionmaker(
  bind=engine,
  expire_on_commit=False,
)

async def check_database_connection()->bool:
  async with engine.connect() as connection:
    await connection.execute(text("select 1"))
  return True
