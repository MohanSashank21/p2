"""Allow persisted Docker investigation evidence.

Revision ID: 7c3e91a4b620
Revises: f2a6d9c1b804
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7c3e91a4b620"
down_revision: Union[str, Sequence[str], None] = "f2a6d9c1b804"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context', 'trace_spans', 'docker_investigation')",
  )


def downgrade() -> None:
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  count = op.get_bind().scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "docker_investigation"),
  )
  if count:
    raise RuntimeError(
      "Cannot downgrade while Docker investigation evidence records exist",
    )

  op.drop_constraint("ck_incident_evidence_type", "incident_evidence", type_="check")
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context', 'trace_spans')",
  )
