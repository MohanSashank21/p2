from collections.abc import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
  AsyncSession,
  async_sessionmaker,
  create_async_engine,
)

from app.core.config import settings

engine = create_async_engine(
  settings.DATABASE_URL,
  pool_pre_ping=True
)

AsyncSessionLocal = async_sessionmaker(
  bind=engine,
  expire_on_commit=False,
)

async def check_database_connection() -> bool:
  async with engine.connect() as connection:
    await connection.execute(text("select 1"))
  return True

async def get_db() -> AsyncGenerator[AsyncSession, None]:
  async with AsyncSessionLocal() as session:
    yield session
