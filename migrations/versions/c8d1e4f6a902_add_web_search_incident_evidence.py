"""Allow persisted, grounded internet-search evidence.

Revision ID: c8d1e4f6a902
Revises: b7e9c2a6d401
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c8d1e4f6a902"
down_revision: Union[str, Sequence[str], None] = "b7e9c2a6d401"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_BASE_EVIDENCE_TYPES = (
  "'manual_report', 'webhook_payload', 'alertmanager_notification', "
  "'grafana_notification', 'loki_logs', 'github_context', 'trace_spans', "
  "'docker_investigation', 'prometheus_metrics', 'github_workflow_event', "
  "'web_search'"
)
_PREVIOUS_EVIDENCE_TYPES = (
  "'manual_report', 'webhook_payload', 'alertmanager_notification', "
  "'grafana_notification', 'loki_logs', 'github_context', 'trace_spans', "
  "'docker_investigation', 'prometheus_metrics', 'github_workflow_event'"
)


def upgrade() -> None:
  with op.batch_alter_table("incident_evidence") as batch_op:
    batch_op.drop_constraint("ck_incident_evidence_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incident_evidence_type",
      f"evidence_type IN ({_BASE_EVIDENCE_TYPES})",
    )
  op.create_index(
    "uq_incident_evidence_web_search_query",
    "incident_evidence",
    ["incident_id", "query_hash"],
    unique=True,
    postgresql_where=sa.text(
      "evidence_type = 'web_search' AND query_hash IS NOT NULL",
    ),
    sqlite_where=sa.text(
      "evidence_type = 'web_search' AND query_hash IS NOT NULL",
    ),
  )


def downgrade() -> None:
  evidence = sa.table(
    "incident_evidence",
    sa.column("evidence_type", sa.String()),
  )
  count = op.get_bind().scalar(
    sa.select(sa.func.count())
    .select_from(evidence)
    .where(evidence.c.evidence_type == "web_search"),
  )
  if count:
    raise RuntimeError(
      "Cannot downgrade while internet-search evidence records exist",
    )

  op.drop_index(
    "uq_incident_evidence_web_search_query",
    table_name="incident_evidence",
  )
  with op.batch_alter_table("incident_evidence") as batch_op:
    batch_op.drop_constraint("ck_incident_evidence_type", type_="check")
    batch_op.create_check_constraint(
      "ck_incident_evidence_type",
      f"evidence_type IN ({_PREVIOUS_EVIDENCE_TYPES})",
    )
