from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKey,
  Index,
  String,
  Uuid,
  func,
  text,
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

class OrganisationInvitation(Base):
  __tablename__ = "organisation_invitations"
  __table_args__ = (
    CheckConstraint(
      "role = 'member'",
      name="ck_organisation_invitations_role",
    ),
    Index(
      "uq_organisation_invitations_pending_target",
      "organisation_id",
      text("lower(email)"),
      unique=True,
      postgresql_where=text("accepted_at IS NULL"),
      sqlite_where=text("accepted_at IS NULL"),
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  organisation_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("organisations.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id", ondelete="CASCADE"),
    nullable=False,
  )
  email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
  role: Mapped[str] = mapped_column(String(20), nullable=False)
  token_hash: Mapped[str] = mapped_column(
    String(64),
    unique=True,
    nullable=False,
  )
  expires_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
  )
  accepted_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
