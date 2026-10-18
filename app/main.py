from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.config import settings
from app.db.database import client
from app.api.router import api_router

@asynccontextmanager
async def lifespan(app:FastAPI):
  await client.admin.command("ping")
  print("MongoDB Atlas Connected")
  yield
  await client.close()

app = FastAPI(title=settings.APP_NAME,version=settings.APP_VERSION,debug=settings.DEBUG,lifespan=lifespan)
app.include_router(api_router)