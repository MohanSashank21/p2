from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.github import GitHubWebhookEvent
from app.services.github_event_processing_service import (
  InvalidGitHubWorkflowEvent,
  process_github_workflow_event,
)

logger = logging.getLogger(__name__)
_POLL_INTERVAL_SECONDS = 1
_LEASE_SECONDS = 60
_MAX_ATTEMPTS = 5
_MAX_RETRY_DELAY_SECONDS = 300


async def _claim_next_event(
  session_factory: async_sessionmaker[AsyncSession],
) -> tuple[uuid.UUID, int] | None:
  now = datetime.now(UTC)
  async with session_factory() as session:
    event = await session.scalar(
      select(GitHubWebhookEvent)
      .where(
        or_(
          GitHubWebhookEvent.processing_status == "pending",
          and_(
            GitHubWebhookEvent.processing_status == "retry",
            GitHubWebhookEvent.available_at <= now,
          ),
          and_(
            GitHubWebhookEvent.processing_status == "processing",
            GitHubWebhookEvent.lease_expires_at <= now,
          ),
        ),
      )
      .order_by(GitHubWebhookEvent.received_at, GitHubWebhookEvent.id)
      .limit(1)
      .with_for_update(skip_locked=True),
    )
    if event is None:
      return None
    if event.attempt_count >= _MAX_ATTEMPTS:
      event.processing_status = "failed"
      event.available_at = None
      event.lease_expires_at = None
      event.last_failure_code = "attempt_limit"
      await session.commit()
      return None
    event.processing_status = "processing"
    event.attempt_count += 1
    event.available_at = None
    event.lease_expires_at = now + timedelta(seconds=_LEASE_SECONDS)
    event.last_failure_code = None
    event_id = event.id
    attempt_count = event.attempt_count
    await session.commit()
  return event_id, attempt_count


async def _record_failure(
  session_factory: async_sessionmaker[AsyncSession],
  event_id: uuid.UUID,
  attempt_count: int,
  *,
  failure_code: str,
  permanent: bool,
) -> None:
  now = datetime.now(UTC)
  async with session_factory() as session:
    event = await session.scalar(
      select(GitHubWebhookEvent)
      .where(GitHubWebhookEvent.id == event_id)
      .with_for_update(),
    )
    if event is None or event.processing_status != "processing":
      return
    if permanent or attempt_count >= _MAX_ATTEMPTS:
      event.processing_status = "failed"
      event.available_at = None
    else:
      retry_seconds = min(
        5 * (2 ** max(0, attempt_count - 1)),
        _MAX_RETRY_DELAY_SECONDS,
      )
      event.processing_status = "retry"
      event.available_at = now + timedelta(seconds=retry_seconds)
    event.lease_expires_at = None
    event.last_failure_code = failure_code[:64]
    await session.commit()


async def process_next_github_event(
  session_factory: async_sessionmaker[AsyncSession],
) -> bool:
  claimed = await _claim_next_event(session_factory)
  if claimed is None:
    return False
  event_id, attempt_count = claimed
  try:
    async with session_factory() as session:
      await process_github_workflow_event(session, event_id)
      await session.commit()
  except InvalidGitHubWorkflowEvent:
    await _record_failure(
      session_factory,
      event_id,
      attempt_count,
      failure_code="invalid_event",
      permanent=True,
    )
    logger.warning(
      "GitHub workflow event was rejected during processing (event_id=%s)",
      event_id,
    )
  except Exception as error:
    await _record_failure(
      session_factory,
      event_id,
      attempt_count,
      failure_code="processing_error",
      permanent=False,
    )
    logger.error(
      "GitHub workflow event processing failed (event_id=%s, category=%s)",
      event_id,
      type(error).__name__,
    )
  return True


async def run_github_event_worker(
  session_factory: async_sessionmaker[AsyncSession],
) -> None:
  while True:
    try:
      did_work = await process_next_github_event(session_factory)
    except asyncio.CancelledError:
      raise
    except Exception as error:
      logger.error(
        "GitHub event worker iteration failed (category=%s)",
        type(error).__name__,
      )
      await asyncio.sleep(_POLL_INTERVAL_SECONDS)
      continue
    if not did_work:
      await asyncio.sleep(_POLL_INTERVAL_SECONDS)
