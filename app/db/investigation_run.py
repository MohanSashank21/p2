from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
  CheckConstraint,
  DateTime,
  ForeignKey,
  Index,
  Integer,
  JSON,
  String,
  Text,
  Uuid,
  UniqueConstraint,
  func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class InvestigationRun(Base):
  __tablename__ = "investigation_runs"
  __table_args__ = (
    CheckConstraint(
      "status IN ('running', 'succeeded', 'partial', 'failed', 'cancelled')",
      name="ck_investigation_runs_status",
    ),
    CheckConstraint(
      "attempt_count >= 1",
      name="ck_investigation_runs_attempt_count",
    ),
    CheckConstraint(
      "synthesis_status IN ('not_started', 'running', 'succeeded', 'failed')",
      name="ck_investigation_runs_synthesis_status",
    ),
    CheckConstraint(
      "synthesis_attempt_count >= 0",
      name="ck_investigation_runs_synthesis_attempt_count",
    ),
    UniqueConstraint(
      "project_id",
      "incident_id",
      "requested_by_user_id",
      "idempotency_key",
      name="uq_investigation_runs_idempotency",
    ),
    Index(
      "ix_investigation_runs_incident_started",
      "incident_id",
      "started_at",
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
  )
  incident_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("incidents.id", ondelete="CASCADE"),
    nullable=False,
  )
  requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id", ondelete="SET NULL"),
    nullable=True,
  )
  idempotency_key: Mapped[str | None] = mapped_column(
    String(128),
    nullable=True,
  )
  request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
  requested_integrations: Mapped[list[str]] = mapped_column(
    JSON,
    nullable=False,
  )
  request_criteria: Mapped[dict] = mapped_column(JSON, nullable=False)
  status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    server_default="running",
  )
  aggregate_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
  integration_results: Mapped[dict | None] = mapped_column(JSON, nullable=True)
  evidence_ids: Mapped[list[str]] = mapped_column(
    JSON,
    nullable=False,
    default=list,
    server_default="[]",
  )
  failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
  failure_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
  attempt_count: Mapped[int] = mapped_column(
    Integer,
    nullable=False,
    default=1,
    server_default="1",
  )
  synthesis_status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    default="not_started",
    server_default="not_started",
  )
  synthesis_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
  synthesis_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
  synthesis_prompt_version: Mapped[str | None] = mapped_column(
    String(32),
    nullable=True,
  )
  synthesis_schema_version: Mapped[str | None] = mapped_column(
    String(32),
    nullable=True,
  )
  synthesis_input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
  synthesis_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
  synthesis_provider_attempts: Mapped[int | None] = mapped_column(
    Integer,
    nullable=True,
  )
  synthesis_attempt_count: Mapped[int] = mapped_column(
    Integer,
    nullable=False,
    default=0,
    server_default="0",
  )
  synthesis_started_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  synthesis_failure_code: Mapped[str | None] = mapped_column(
    String(64),
    nullable=True,
  )
  synthesis_completed_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  started_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  completed_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
