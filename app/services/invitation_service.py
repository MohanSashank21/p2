import hashlib

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def lock_invitation_target(
  session: AsyncSession,
  scope: str,
  target: str,
) -> None:
  if session.get_bind().dialect.name != "postgresql":
    return
  digest = hashlib.sha256(f"{scope}:{target}".encode("utf-8")).digest()
  lock_id = int.from_bytes(digest[:8], byteorder="big", signed=True)
  await session.execute(
    text("SELECT pg_advisory_xact_lock(:lock_id)"),
    {"lock_id": lock_id},
  )
