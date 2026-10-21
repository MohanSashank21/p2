from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import (
  DateTime,
  ForeignKey,
  String,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base

class RefreshSession(Base):
  __tablename__ = "refresh_sessions"

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  family_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    nullable=False,
    index=True,
  )
  user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  token_hash: Mapped[str] = mapped_column(
    String(64),
    unique=True,
    nullable=False,
  )
  expires_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
  )
  revoked_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("refresh_sessions.id"),
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
