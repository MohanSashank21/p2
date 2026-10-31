from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
  Boolean,
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


class IncidentSource(Base):
  __tablename__ = "incident_sources"
  __table_args__ = (
    UniqueConstraint(
      "project_id",
      "name",
      name="uq_incident_sources_project_name",
    ),
    CheckConstraint(
      "trace_connection_status IN ('not_checked', 'connected', 'unavailable')",
      name="ck_incident_sources_trace_connection_status",
    ),
    CheckConstraint(
      "prometheus_connection_status IN ('not_checked', 'connected', 'unavailable')",
      name="ck_incident_sources_prometheus_connection_status",
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
  environment_id: Mapped[uuid.UUID | None] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("environments.id", ondelete="SET NULL"),
    nullable=True,
    index=True,
  )
  name: Mapped[str] = mapped_column(String(120), nullable=False)
  source_type: Mapped[str] = mapped_column(
    String(40),
    nullable=False,
    default="generic_webhook",
    server_default="generic_webhook",
  )
  loki_url: Mapped[str | None] = mapped_column(Text, nullable=True)
  loki_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
  loki_auth_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
  loki_auth_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
  prometheus_url: Mapped[str | None] = mapped_column(Text, nullable=True)
  prometheus_auth_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
  prometheus_auth_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
  prometheus_connection_status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    default="not_checked",
    server_default="not_checked",
  )
  prometheus_last_checked_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  trace_backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
  trace_url: Mapped[str | None] = mapped_column(Text, nullable=True)
  trace_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
  trace_auth_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
  trace_auth_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
  trace_service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
  trace_resource_attributes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
  trace_connection_status: Mapped[str] = mapped_column(
    String(16),
    nullable=False,
    default="not_checked",
    server_default="not_checked",
  )
  trace_last_checked_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  credential_hash: Mapped[str] = mapped_column(String(64), nullable=False)
  enabled: Mapped[bool] = mapped_column(
    Boolean,
    nullable=False,
    default=True,
    server_default="true",
  )
  created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )
  events: Mapped[list["SourceEvent"]] = relationship(
    back_populates="source",
    cascade="all, delete-orphan",
    passive_deletes=True,
  )


class SourceEvent(Base):
  __tablename__ = "source_events"
  __table_args__ = (
    UniqueConstraint(
      "source_id",
      "external_event_id",
      name="uq_source_events_source_external_id",
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  source_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("incident_sources.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
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
  external_event_id: Mapped[str | None] = mapped_column(
    String(255),
    nullable=True,
  )
  event_type: Mapped[str] = mapped_column(String(64), nullable=False)
  title: Mapped[str] = mapped_column(String(255), nullable=False)
  description: Mapped[str | None] = mapped_column(Text, nullable=True)
  severity: Mapped[str] = mapped_column(String(16), nullable=False)
  original_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
  received_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
  )

  source: Mapped[IncidentSource] = relationship(back_populates="events")


class ProviderAlert(Base):
  __tablename__ = "alertmanager_alerts"
  __table_args__ = (
    UniqueConstraint(
      "source_id",
      "fingerprint",
      name="uq_alertmanager_alerts_source_fingerprint",
    ),
    CheckConstraint(
      "status IN ('firing', 'resolved')",
      name="ck_alertmanager_alerts_status",
    ),
  )

  id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    primary_key=True,
    default=uuid.uuid4,
  )
  source_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("incident_sources.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  project_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("projects.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  incident_id: Mapped[uuid.UUID] = mapped_column(
    Uuid(as_uuid=True),
    ForeignKey("incidents.id", ondelete="CASCADE"),
    nullable=False,
    index=True,
  )
  fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
  status: Mapped[str] = mapped_column(String(16), nullable=False)
  alert_name: Mapped[str] = mapped_column(String(255), nullable=False)
  severity: Mapped[str] = mapped_column(String(16), nullable=False)
  summary: Mapped[str | None] = mapped_column(Text, nullable=True)
  description: Mapped[str | None] = mapped_column(Text, nullable=True)
  labels: Mapped[dict] = mapped_column(JSON, nullable=False)
  annotations: Mapped[dict] = mapped_column(JSON, nullable=False)
  starts_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
  )
  ends_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )
  generator_url: Mapped[str | None] = mapped_column(Text, nullable=True)
  latest_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
  first_received_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
  )
  last_received_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
  )
  resolved_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
  )


AlertmanagerAlert = ProviderAlert
