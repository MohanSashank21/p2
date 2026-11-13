from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy.engine import make_url


def postgres_checkpoint_connection_string(database_url: str) -> str:
  url = make_url(database_url)
  if not url.drivername.startswith("postgresql"):
    raise ValueError("Durable investigation checkpoints require PostgreSQL.")
  return url.set(drivername="postgresql").render_as_string(
    hide_password=False,
  )


@asynccontextmanager
async def open_postgres_investigation_checkpointer(
  database_url: str,
) -> AsyncIterator[AsyncPostgresSaver]:
  connection_string = postgres_checkpoint_connection_string(database_url)
  async with AsyncPostgresSaver.from_conn_string(connection_string) as saver:
    await saver.setup()
    yield saver
