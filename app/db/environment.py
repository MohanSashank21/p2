from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
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
  from app.db.project import Project

class Environment(Base):
  __tablename__ = "environments"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "name",
      name="uq_environments_project_name",
    ),
  )
  
  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  
  project_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("projects.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  name: Mapped[str] = mapped_column(
    String(80),
    nullable=False,
  )
  environment_type: Mapped[str] = mapped_column(
    String(30),
    nullable=False,
  )
  base_url: Mapped[str | None] = mapped_column(
    String(500),
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  project: Mapped["Project"] = relationship(
    "Project",
    back_populates="environments",
  )
