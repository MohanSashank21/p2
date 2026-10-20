from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKey,
  ForeignKeyConstraint,
  String,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ProjectInvitation(Base):
  __tablename__ = "project_invitations"
  __table_args__ = (
    CheckConstraint(
      """
      (role = 'manager'
        AND project_id IS NULL
        AND proposed_project_name IS NOT NULL)
      OR
      (role = 'worker'
        AND project_id IS NOT NULL
        AND proposed_project_name IS NULL
        AND proposed_project_description IS NULL)
      """,
      name="ck_project_invitations_role_target",
    ),
    CheckConstraint(
      """
      (accepted_at IS NULL AND accepted_project_id IS NULL)
      OR
      (accepted_at IS NOT NULL AND accepted_project_id IS NOT NULL)
      """,
      name="ck_project_invitations_acceptance_state",
    ),
    ForeignKeyConstraint(
      ["organisation_id", "invitee_user_id"],
      ["memberships.organisation_id", "memberships.user_id"],
      name="fk_project_invitations_organisation_invitee",
      ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
      ["project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_invitations_project_organisation",
      ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
      ["accepted_project_id", "organisation_id"],
      ["projects.id", "projects.organisation_id"],
      name="fk_project_invitations_accepted_project_organisation",
      ondelete="CASCADE",
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
  project_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    nullable=True,
    index=True,
  )
  accepted_project_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    nullable=True,
  )
  invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id", ondelete="CASCADE"),
    nullable=False,
  )
  invitee_user_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    nullable=False,
    index=True,
  )
  role: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
  )
  proposed_project_name: Mapped[str | None] = mapped_column(
    String(120),
    nullable=True,
  )
  proposed_project_description: Mapped[str | None] = mapped_column(
    String(4000),
    nullable=True,
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
  accepted_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
