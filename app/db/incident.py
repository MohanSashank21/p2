from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Incident(Base):
  __tablename__ = "incidents"
  __table_args__ = (
    CheckConstraint(
      "source_type IN ('manual', 'generic_webhook')",
      name="ck_incidents_source_type",
    ),
    CheckConstraint(
      "severity IN ('low', 'medium', 'high', 'critical')",
      name="ck_incidents_severity",
    ),
    CheckConstraint(
      "status IN ('open', 'acknowledged', 'resolved')",
      name="ck_incidents_status",
    ),
    UniqueConstraint("source_event_id", name="uq_incidents_source_event_id"),
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
  environment_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("environments.id", ondelete="SET NULL"),
    nullable=True,
    index=True,
  )
  source_event_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("source_events.id", ondelete="SET NULL"),
    nullable=True,
  )
  reported_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("users.id", ondelete="SET NULL"),
    nullable=True,
    index=True,
  )
  source_type: Mapped[str] = mapped_column(String(40), nullable=False)
  incident_type: Mapped[str] = mapped_column(String(64), nullable=False)
  title: Mapped[str] = mapped_column(String(255), nullable=False)
  description: Mapped[str | None] = mapped_column(Text, nullable=True)
  severity: Mapped[str] = mapped_column(String(16), nullable=False)
  status: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
    default="open",
    server_default="open",
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
  resolved_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )

  evidence: Mapped[list["IncidentEvidence"]] = relationship(
    back_populates="incident",
    cascade="all, delete-orphan",
    passive_deletes=True,
    order_by="IncidentEvidence.created_at",
  )


class IncidentEvidence(Base):
  __tablename__ = "incident_evidence"
  __table_args__ = (
    CheckConstraint(
      "evidence_type IN ('manual_report', 'webhook_payload')",
      name="ck_incident_evidence_type",
    ),
    UniqueConstraint(
      "source_event_id",
      name="uq_incident_evidence_source_event_id",
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  incident_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("incidents.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  source_event_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("source_events.id", ondelete="SET NULL"),
    nullable=True,
  )
  evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
  original_content: Mapped[dict] = mapped_column(JSON, nullable=False)
  normalized_content: Mapped[dict] = mapped_column(JSON, nullable=False)
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )

  incident: Mapped[Incident] = relationship(back_populates="evidence")
