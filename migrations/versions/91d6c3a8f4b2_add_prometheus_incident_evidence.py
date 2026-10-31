"""Allow persisted Prometheus metric evidence.

Revision ID: 91d6c3a8f4b2
Revises: 6e2b9a4c1d73
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "91d6c3a8f4b2"
down_revision: Union[str, Sequence[str], None] = "6e2b9a4c1d73"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.drop_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    type_="check",
  )
  op.create_check_constraint(
    "ck_incident_evidence_type",
    "incident_evidence",
    "evidence_type IN ('manual_report', 'webhook_payload', "
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context', 'trace_spans', 'docker_investigation', "
    "'prometheus_metrics')",
  )


def downgrade() -> None:
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  count = op.get_bind().scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "prometheus_metrics"),
  )
  if count:
    raise RuntimeError(
      "Cannot downgrade while Prometheus metric evidence records exist",
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
    "'alertmanager_notification', 'grafana_notification', 'loki_logs', "
    "'github_context', 'trace_spans', 'docker_investigation')",
  )
