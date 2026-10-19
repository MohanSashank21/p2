from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKey,
  String,
  UniqueConstraint,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
  from app.db.organisation import Organisation
  from app.db.user import User


class Membership(Base):
  __tablename__ = "memberships"
  __table_args__ = (
    UniqueConstraint(
      "organisation_id",
      "user_id",
      name="uq_memberships_organisation_user",
    ),
    CheckConstraint(
      "role IN ('owner', 'admin', 'worker')",
      name="ck_memberships_role",
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

  organisation: Mapped["Organisation"] = relationship(
    "Organisation",
    back_populates="memberships",
  )
  user: Mapped["User"] = relationship(
    "User",
    back_populates="memberships",
  )
