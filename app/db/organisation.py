from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
  from app.db.membership import Membership
  from app.db.project import Project


class Organisation(Base):
  __tablename__ = "organisations"

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  name: Mapped[str] = mapped_column(
    String(120),
    nullable=False,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )

  memberships: Mapped[list["Membership"]] = relationship(
    "Membership",
    back_populates="organisation",
  )
  projects: Mapped[list["Project"]] = relationship(
    "Project",
    back_populates="organisation",
  )
