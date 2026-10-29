"""Allow Grafana incidents and notification evidence.

Revision ID: a7c9e82f14b6
Revises: 6bf1d3a42c78
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7c9e82f14b6"
down_revision: Union[str, Sequence[str], None] = "6bf1d3a42c78"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.drop_constraint("ck_incidents_source_type", "incidents", type_="check")
  op.create_check_constraint(
    "ck_incidents_source_type",
    "incidents",
    "source_type IN ('manual', 'generic_webhook', 'alertmanager', 'grafana')",
  )
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification')",
  )


def downgrade() -> None:
  connection = op.get_bind()
  incidents = sa.table(
    "incidents",
    sa.column("source_type", sa.String()),
  )
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  has_grafana_incidents = connection.scalar(
    sa.select(sa.func.count())
    .select_from(incidents)
    .where(incidents.c.source_type == "grafana"),
  )
  has_grafana_evidence = connection.scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "grafana_notification"),
  )
  if has_grafana_incidents or has_grafana_evidence:
    raise RuntimeError(
      "Cannot downgrade while Grafana incident or evidence records exist",
    )

  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification')",
  )
  op.drop_constraint("ck_incidents_source_type", "incidents", type_="check")
  op.create_check_constraint(
    "ck_incidents_source_type",
    "incidents",
    "source_type IN ('manual', 'generic_webhook', 'alertmanager')",
  )
