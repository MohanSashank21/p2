"""Add Alertmanager alerts and persisted notification history.

Revision ID: 6bf1d3a42c78
Revises: e2a4c8910b7f
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6bf1d3a42c78"
down_revision: Union[str, Sequence[str], None] = "e2a4c8910b7f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.drop_constraint("ck_incidents_source_type", "incidents", type_="check")
  op.create_check_constraint(
    "ck_incidents_source_type",
    "incidents",
    "source_type IN ('manual', 'generic_webhook', 'alertmanager')",
  )
  op.drop_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    type_="check",
  )
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification')",
  )
  op.create_table(
    "alertmanager_alerts",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("source_id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("incident_id", sa.Uuid(), nullable=False),
    sa.Column("fingerprint", sa.String(length=255), nullable=False),
    sa.Column("status", sa.String(length=16), nullable=False),
    sa.Column("alert_name", sa.String(length=255), nullable=False),
    sa.Column("severity", sa.String(length=16), nullable=False),
    sa.Column("summary", sa.Text(), nullable=True),
    sa.Column("description", sa.Text(), nullable=True),
    sa.Column("labels", sa.JSON(), nullable=False),
    sa.Column("annotations", sa.JSON(), nullable=False),
    sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("generator_url", sa.Text(), nullable=True),
    sa.Column("latest_payload", sa.JSON(), nullable=False),
    sa.Column("first_received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint(
      "status IN ('firing', 'resolved')",
      name="ck_alertmanager_alerts_status",
    ),
    sa.ForeignKeyConstraint(
      ["incident_id"],
      ["incidents.id"],
      name="fk_alertmanager_alerts_incident_id_incidents",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      name="fk_alertmanager_alerts_project_id_projects",
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["source_id"],
      ["incident_sources.id"],
      name="fk_alertmanager_alerts_source_id_incident_sources",
      ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("id", name="pk_alertmanager_alerts"),
    sa.UniqueConstraint(
      "source_id",
      "fingerprint",
      name="uq_alertmanager_alerts_source_fingerprint",
    ),
  )
  op.create_index(
    "ix_alertmanager_alerts_incident_id",
    "alertmanager_alerts",
    ["incident_id"],
  )
  op.create_index(
    "ix_alertmanager_alerts_project_id",
    "alertmanager_alerts",
    ["project_id"],
  )
  op.create_index(
    "ix_alertmanager_alerts_source_id",
    "alertmanager_alerts",
    ["source_id"],
  )
  op.add_column(
    "incident_evidence",
    sa.Column("alertmanager_alert_id", sa.Uuid(), nullable=True),
  )
  op.add_column(
    "incident_evidence",
    sa.Column("payload_hash", sa.String(length=64), nullable=True),
  )
  op.create_foreign_key(
    "fk_incident_evidence_alertmanager_alert_id_alertmanager_alerts",
    "incident_evidence",
    "alertmanager_alerts",
    ["alertmanager_alert_id"],
    ["id"],
    ondelete="SET NULL",
  )
  op.create_unique_constraint(
    "uq_incident_evidence_alertmanager_payload",
    "incident_evidence",
    ["alertmanager_alert_id", "payload_hash"],
  )


def downgrade() -> None:
  connection = op.get_bind()
  alertmanager_alerts = sa.table(
    "alertmanager_alerts",
    sa.column("id", sa.Uuid()),
  )
  alertmanager_incidents = sa.table(
    "incidents",
    sa.column("id", sa.Uuid()),
    sa.column("source_type", sa.String()),
  )
  alertmanager_evidence = sa.table(
    "incident_evidence",
    sa.column("id", sa.Uuid()),
    sa.column("evidence_type", sa.String()),
  )
  has_alerts = connection.scalar(
    sa.select(sa.func.count()).select_from(alertmanager_alerts),
  )
  has_incidents = connection.scalar(
    sa.select(sa.func.count())
    .select_from(alertmanager_incidents)
    .where(alertmanager_incidents.c.source_type == "alertmanager"),
  )
  has_evidence = connection.scalar(
    sa.select(sa.func.count())
    .select_from(alertmanager_evidence)
    .where(
      alertmanager_evidence.c.evidence_type == "alertmanager_notification",
    ),
  )
  if has_alerts or has_incidents or has_evidence:
    raise RuntimeError(
      "Cannot downgrade while Alertmanager alert, incident, or evidence "
      "records exist",
    )

  op.drop_constraint(
    "uq_incident_evidence_alertmanager_payload",
    "incident_evidence",
    type_="unique",
  )
  op.drop_constraint(
    "fk_incident_evidence_alertmanager_alert_id_alertmanager_alerts",
    "incident_evidence",
    type_="foreignkey",
  )
  op.drop_column("incident_evidence", "payload_hash")
  op.drop_column("incident_evidence", "alertmanager_alert_id")
  op.drop_index("ix_alertmanager_alerts_source_id", table_name="alertmanager_alerts")
  op.drop_index("ix_alertmanager_alerts_project_id", table_name="alertmanager_alerts")
  op.drop_index("ix_alertmanager_alerts_incident_id", table_name="alertmanager_alerts")
  op.drop_table("alertmanager_alerts")
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload')",
  )
  op.drop_constraint("ck_incidents_source_type", "incidents", type_="check")
  op.create_check_constraint(
    "ck_incidents_source_type",
    "incidents",
    "source_type IN ('manual', 'generic_webhook')",
  )
