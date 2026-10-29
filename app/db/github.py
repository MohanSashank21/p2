from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
  BigInteger,
  CheckConstraint,
  DateTime,
  ForeignKey,
  JSON,
  String,
  Text,
  UniqueConstraint,
  Uuid,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class GitHubInstallation(Base):
  __tablename__ = "github_installations"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "installation_id",
      name="uq_github_installations_project_installation",
    ),
    CheckConstraint(
      "status IN ('active', 'disconnected')",
      name="ck_github_installations_status",
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
  installation_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
  account_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
  account_login: Mapped[str] = mapped_column(String(255), nullable=False)
  status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    default="active",
    server_default="active",
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  updated_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    onupdate=func.now(),
    nullable=False,
  )


class GitHubRepository(Base):
  __tablename__ = "github_repositories"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "github_repo_id",
      name="uq_github_repositories_project_repo",
    ),
    CheckConstraint(
      "status IN ('active', 'disconnected')",
      name="ck_github_repositories_status",
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
  installation_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("github_installations.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  github_repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
  full_name: Mapped[str] = mapped_column(String(512), nullable=False)
  owner: Mapped[str] = mapped_column(String(255), nullable=False)
  default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
  html_url: Mapped[str] = mapped_column(Text, nullable=False)
  status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    default="active",
    server_default="active",
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  updated_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    onupdate=func.now(),
    nullable=False,
  )


class GitHubWebhookEvent(Base):
  __tablename__ = "github_webhook_events"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "delivery_id",
      name="uq_github_webhook_events_project_delivery",
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
  github_repository_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("github_repositories.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
  event_name: Mapped[str] = mapped_column(String(64), nullable=False)
  action: Mapped[str | None] = mapped_column(String(64), nullable=True)
  payload: Mapped[dict] = mapped_column(JSON, nullable=False)
  received_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
