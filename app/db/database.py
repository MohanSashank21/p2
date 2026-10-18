from pymongo import AsyncMongoClient
from app.core.config import settings

client = AsyncMongoClient(
  settings.MONGO_URI,
  serverSelectionTimeoutMS=5000
)

database = client[settings.DATABASE_NAME]

async def check_database_connection()->bool:
  await client.admin.command("ping")
  return True
