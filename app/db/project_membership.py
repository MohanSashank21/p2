from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKeyConstraint,
  String,
  UniqueConstraint,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
if TYPE_CHECKING:
  from app.db.project import Project
  from app.db.user import User


class ProjectMembership(Base):
  __tablename__ = "project_memberships"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "user_id",
      name="uq_project_memberships_project_user",
    ),
    CheckConstraint(
      "role IN ('manager', 'worker')",
      name="ck_project_memberships_role",
    ),
    ForeignKeyConstraint(
      ["project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_memberships_project_organisation",
      ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
      ["organisation_id", "user_id"],
      ["memberships.organisation_id", "memberships.user_id"],
      name="fk_project_memberships_organisation_user",
      ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
      ["user_id"],
      ["users.id"],
      name="fk_project_memberships_user",
      ondelete="CASCADE",
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  project_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    nullable=False,
    index=True,
  )
  organisation_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    nullable=False,
  )
  user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
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
  project: Mapped["Project"] = relationship(
    "Project",
    back_populates="memberships",
  )
  user: Mapped["User"] = relationship(
    "User",
    back_populates="project_memberships",
  )
