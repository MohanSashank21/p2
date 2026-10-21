import asyncio
import base64
import hashlib
import hmac
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.core.exceptions import EmailDeliveryError
from app.db.auth import OrganisationInvitation
from app.db.email_outbox import EmailOutbox
from app.db.organisation import Organisation
from app.db.project import Project
from app.db.project_invitation import ProjectInvitation
from app.services.email_service import send_email
from app.services.invitation_service import lock_invitation_target

logger = logging.getLogger(__name__)
MAX_ATTEMPTS = 5
POLL_INTERVAL_SECONDS = 5
MAX_MESSAGES_PER_POLL = 20
EmailSender = Callable[[str, str, str], Awaitable[None]]


def _invitation_token(outbox_id: uuid.UUID) -> str:
  secret = settings.OTP_HASH_SECRET_KEY
  if secret is None or len(secret.get_secret_value().encode("utf-8")) < 32:
    raise RuntimeError("OTP_HASH_SECRET_KEY must contain at least 32 bytes")
  digest = hmac.new(
    secret.get_secret_value().encode("utf-8"),
    f"invitation-email:{outbox_id}".encode("utf-8"),
    hashlib.sha256,
  ).digest()
  return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _hash_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def enqueue_invitation_email(
  session: AsyncSession,
  invitation: OrganisationInvitation | ProjectInvitation,
  *,
  invitation_type: str,
  recipient: str,
  subject: str,
  message: str,
  accept_path: str,
  target_scope: str,
  target_key: str,
  expiry_days: int,
  sender: EmailSender = send_email,
) -> EmailOutbox:
  session.add(invitation)
  await session.flush()
  await session.execute(
    update(EmailOutbox)
    .where(
      EmailOutbox.target_scope == target_scope,
      EmailOutbox.target_key == target_key,
      EmailOutbox.status == "queued",
    )
    .values(status="superseded"),
  )
  outbox = EmailOutbox(
    id=uuid.uuid4(),
    invitation_type=invitation_type,
    invitation_id=invitation.id,
    recipient=recipient,
    subject=subject,
    body_template=(
      f"{message}\n\n"
      "Sign in to OpsPilot with this email and accept the invitation here:\n"
      "{accept_url}\n\n"
      f"This invitation expires in {expiry_days} days."
    ),
    accept_path=accept_path,
    target_scope=target_scope,
    target_key=target_key,
  )
  raw_token = _invitation_token(outbox.id)
  invitation.token_hash = _hash_token(raw_token)
  invitation.expires_at = datetime.now(timezone.utc) + timedelta(days=expiry_days)
  session.add(outbox)
  session.add(invitation)
  await session.commit()
  await deliver_outbox_message(session, outbox.id, sender)
  return outbox


async def _load_invitation(
  session: AsyncSession,
  outbox: EmailOutbox,
) -> OrganisationInvitation | ProjectInvitation | None:
  model = (
    OrganisationInvitation
    if outbox.invitation_type == "organisation"
    else ProjectInvitation
  )
  return await session.scalar(
    select(model).where(model.id == outbox.invitation_id).with_for_update(),
  )


async def deliver_outbox_message(
  session: AsyncSession,
  outbox_id: uuid.UUID,
  sender: EmailSender = send_email,
) -> bool:
  candidate = await session.get(EmailOutbox, outbox_id)
  if candidate is None:
    return False
  await lock_invitation_target(
    session,
    candidate.target_scope,
    candidate.target_key,
  )
  outbox = await session.scalar(
    select(EmailOutbox)
    .where(EmailOutbox.id == outbox_id)
    .with_for_update()
    .execution_options(populate_existing=True),
  )
  now = datetime.now(timezone.utc)
  available_at = outbox.available_at if outbox is not None else now
  if available_at.tzinfo is None:
    available_at = available_at.replace(tzinfo=timezone.utc)
  if (
    outbox is None
    or outbox.status != "queued"
    or available_at > now
  ):
    return False
  invitation = await _load_invitation(session, outbox)
  if invitation is None or invitation.accepted_at is not None:
    outbox.status = "superseded"
    await session.commit()
    return False
  expires_at = invitation.expires_at
  if expires_at.tzinfo is None:
    expires_at = expires_at.replace(tzinfo=timezone.utc)
  if expires_at <= now:
    outbox.status = "superseded"
    await session.commit()
    return False

  token = _invitation_token(outbox.id)
  invitation.token_hash = _hash_token(token)
  accept_url = (
    f"{settings.FRONTEND_BASE_URL.rstrip('/')}{outbox.accept_path}?"
    f"{urlencode({'token': token})}"
  )
  outbox.attempts += 1
  try:
    await sender(
      outbox.recipient,
      outbox.subject,
      outbox.body_template.format(accept_url=accept_url),
    )
  except EmailDeliveryError as error:
    outbox.last_error = str(error)[:1000]
    if outbox.attempts >= MAX_ATTEMPTS:
      outbox.status = "failed"
    else:
      retry_seconds = min(60 * (2 ** (outbox.attempts - 1)), 3600)
      outbox.available_at = now + timedelta(seconds=retry_seconds)
  else:
    outbox.status = "sent"
    outbox.sent_at = now
    outbox.last_error = None
  await session.commit()
  return outbox.status == "sent"


async def process_email_outbox(
  session_factory: async_sessionmaker[AsyncSession],
) -> None:
  for _ in range(MAX_MESSAGES_PER_POLL):
    async with session_factory() as session:
      now = datetime.now(timezone.utc)
      outbox_id = await session.scalar(
        select(EmailOutbox.id)
        .where(
          EmailOutbox.status == "queued",
          EmailOutbox.available_at <= now,
        )
        .order_by(EmailOutbox.available_at, EmailOutbox.created_at)
        .limit(1),
      )
      if outbox_id is None:
        return
      await deliver_outbox_message(session, outbox_id, send_email)


async def run_email_outbox_worker(
  session_factory: async_sessionmaker[AsyncSession],
) -> None:
  while True:
    try:
      await process_email_outbox(session_factory)
    except Exception:
      logger.exception("Invitation email outbox processing failed")
    await asyncio.sleep(POLL_INTERVAL_SECONDS)
