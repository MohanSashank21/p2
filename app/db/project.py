from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
  DateTime,
  ForeignKey,
  String,
  Text,
  UniqueConstraint,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
  from app.db.environment import Environment
  from app.db.organisation import Organisation
  from app.db.project_membership import ProjectMembership

class Project(Base):
  __tablename__ = "projects"
  __table_args__ = (
    UniqueConstraint(
      "organisation_id",
      "name",
      name="uq_projects_organisation_name",
    ),
    UniqueConstraint(
      "id",
      "organisation_id",
      name="uq_projects_id_organisation",
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

  organisation: Mapped["Organisation"] = relationship(
    "Organisation",
    back_populates="projects",
  )
  environments: Mapped[list["Environment"]] = relationship(
    "Environment",
    back_populates="project",
  )
  memberships: Mapped[list["ProjectMembership"]] = relationship(
    "ProjectMembership",
    back_populates="project",
  )
