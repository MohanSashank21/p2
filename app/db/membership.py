from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKey,
  Index,
  String,
  UniqueConstraint,
  Uuid,
  func,
  text,
)

from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base

class Membership(Base):
  __tablename__ = "memberships"
  __table_args__ = (
    UniqueConstraint(
      "organisation_id",
      "user_id",
      name="uq_memberships_organisation_user",
    ),
    CheckConstraint(
      "role IN ('owner', 'member')",
      name="ck_memberships_role",
    ),
    Index(
      "uq_memberships_single_owner_per_organisation",
      "organisation_id",
      unique=True,
      postgresql_where=text("role = 'owner'"),
      sqlite_where=text("role = 'owner'"),
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  organisation_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("organisations.id"),
    nullable=False,
    index=True,
  )
  user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id"),
    nullable=False,
    index=True,
  )
  role: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
