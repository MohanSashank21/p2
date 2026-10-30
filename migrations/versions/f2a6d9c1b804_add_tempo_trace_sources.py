"""Add Tempo trace source configuration and incident evidence.

Revision ID: f2a6d9c1b804
Revises: e91a3c5d7b42
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f2a6d9c1b804"
down_revision: Union[str, Sequence[str], None] = "e91a3c5d7b42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "incident_sources",
    sa.Column("trace_backend", sa.String(length=32), nullable=True),
  )
  op.add_column("incident_sources", sa.Column("trace_url", sa.Text(), nullable=True))
  op.add_column(
    "incident_sources",
    sa.Column("trace_tenant_id", sa.String(length=255), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("trace_auth_type", sa.String(length=16), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("trace_auth_ciphertext", sa.Text(), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("trace_service_name", sa.String(length=255), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("trace_resource_attributes", sa.JSON(), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column(
      "trace_connection_status",
      sa.String(length=16),
      server_default="not_checked",
      nullable=False,
    ),
  )
  op.add_column(
    "incident_sources",
    sa.Column("trace_last_checked_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.create_check_constraint(
    "ck_incident_sources_trace_connection_status",
    "incident_sources",
    "trace_connection_status IN ('not_checked', 'connected', 'unavailable')",
  )
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context', 'trace_spans')",
  )


def downgrade() -> None:
  connection = op.get_bind()
  sources = sa.table(
    "incident_sources",
    sa.column("source_type", sa.String()),
  )
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  has_trace_sources = connection.scalar(
    sa.select(sa.func.count())
    .select_from(sources)
    .where(sources.c.source_type == "traces"),
  )
  has_trace_evidence = connection.scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "trace_spans"),
  )
  if has_trace_sources or has_trace_evidence:
    raise RuntimeError(
      "Cannot downgrade while trace sources or trace evidence records exist",
    )

  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context')",
  )
  op.drop_constraint(
    "ck_incident_sources_trace_connection_status",
    "incident_sources",
    type_="check",
  )
  op.drop_column("incident_sources", "trace_last_checked_at")
  op.drop_column("incident_sources", "trace_connection_status")
  op.drop_column("incident_sources", "trace_resource_attributes")
  op.drop_column("incident_sources", "trace_service_name")
  op.drop_column("incident_sources", "trace_auth_ciphertext")
  op.drop_column("incident_sources", "trace_auth_type")
  op.drop_column("incident_sources", "trace_tenant_id")
  op.drop_column("incident_sources", "trace_url")
  op.drop_column("incident_sources", "trace_backend")
