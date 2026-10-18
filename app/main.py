from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.config import settings
from app.db.database import engine,check_database_connection
from app.api.router import api_router

@asynccontextmanager
async def lifespan(app:FastAPI):
  await check_database_connection()
  print("postgres Connected")
  try:
    yield
  finally:
    await engine.dispose()

app = FastAPI(title=settings.APP_NAME,version=settings.APP_VERSION,debug=settings.DEBUG,lifespan=lifespan)

app.include_router(api_router)
