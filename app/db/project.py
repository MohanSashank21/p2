from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
  DateTime,
  String,
  Text,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
  from app.db.environment import Environment
  from app.db.project_membership import ProjectMembership

class Project(Base):
  __tablename__ = "projects"

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  name: Mapped[str] = mapped_column(
    String(120),
    nullable=False,
  )
  description: Mapped[str | None] = mapped_column(
    Text,
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )

  environments: Mapped[list["Environment"]] = relationship(
    "Environment",
    back_populates="project",
    cascade="all, delete-orphan",
    passive_deletes=True,
  )
  memberships: Mapped[list["ProjectMembership"]] = relationship(
    "ProjectMembership",
    back_populates="project",
    cascade="all, delete-orphan",
    passive_deletes=True,
  )
