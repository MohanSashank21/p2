"""Add Loki source configuration and incident log evidence.

Revision ID: c4d2a7b91e63
Revises: a7c9e82f14b6
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4d2a7b91e63"
down_revision: Union[str, Sequence[str], None] = "a7c9e82f14b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column("incident_sources", sa.Column("loki_url", sa.Text(), nullable=True))
  op.add_column(
    "incident_sources",
    sa.Column("loki_tenant_id", sa.String(length=255), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("loki_auth_type", sa.String(length=16), nullable=True),
  )
  op.add_column(
    "incident_sources",
    sa.Column("loki_auth_ciphertext", sa.Text(), nullable=True),
  )
  op.add_column(
    "incident_evidence",
    sa.Column("incident_source_id", sa.Uuid(), nullable=True),
  )
  op.add_column(
    "incident_evidence",
    sa.Column("query_hash", sa.String(length=64), nullable=True),
  )
  op.create_foreign_key(
    "fk_incident_evidence_incident_source_id_incident_sources",
    "incident_evidence",
    "incident_sources",
    ["incident_source_id"],
    ["id"],
    ondelete="SET NULL",
  )
  op.create_unique_constraint(
    "uq_incident_evidence_loki_query",
    "incident_evidence",
    ["incident_source_id", "incident_id", "query_hash"],
  )
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs')",
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
  has_loki_sources = connection.scalar(
    sa.select(sa.func.count())
    .select_from(sources)
    .where(sources.c.source_type == "loki"),
  )
  has_loki_evidence = connection.scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "loki_logs"),
  )
  if has_loki_sources or has_loki_evidence:
    raise RuntimeError(
      "Cannot downgrade while Loki source or log evidence records exist",
    )

  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification')",
  )
  op.drop_constraint(
    "uq_incident_evidence_loki_query",
    "incident_evidence",
    type_="unique",
  )
  op.drop_constraint(
    "fk_incident_evidence_incident_source_id_incident_sources",
    "incident_evidence",
    type_="foreignkey",
  )
  op.drop_column("incident_evidence", "query_hash")
  op.drop_column("incident_evidence", "incident_source_id")
  op.drop_column("incident_sources", "loki_auth_ciphertext")
  op.drop_column("incident_sources", "loki_auth_type")
  op.drop_column("incident_sources", "loki_tenant_id")
  op.drop_column("incident_sources", "loki_url")
