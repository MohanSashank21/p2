from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EmailOutbox(Base):
  __tablename__ = "email_outbox"
  __table_args__ = (
    CheckConstraint(
      "status IN ('queued', 'sent', 'failed', 'superseded')",
      name="ck_email_outbox_status",
    ),
    CheckConstraint(
      "invitation_type IN ('organisation', 'project')",
      name="ck_email_outbox_invitation_type",
    ),
    Index("ix_email_outbox_due", "status", "available_at"),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  invitation_type: Mapped[str] = mapped_column(String(20), nullable=False)
  invitation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
  recipient: Mapped[str] = mapped_column(String(320), nullable=False)
  subject: Mapped[str] = mapped_column(String(998), nullable=False)
  body_template: Mapped[str] = mapped_column(Text, nullable=False)
  accept_path: Mapped[str] = mapped_column(String(120), nullable=False)
  target_scope: Mapped[str] = mapped_column(String(40), nullable=False)
  target_key: Mapped[str] = mapped_column(String(500), nullable=False)
  status: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
    default="queued",
    server_default="queued",
  )
  attempts: Mapped[int] = mapped_column(
    Integer,
    nullable=False,
    default=0,
    server_default="0",
  )
  available_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=func.now(),
  )
  sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
  last_error: Mapped[str | None] = mapped_column(String(1000))
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=func.now(),
  )
