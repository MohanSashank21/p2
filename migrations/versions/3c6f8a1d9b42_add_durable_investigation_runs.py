"""Add durable synchronous investigation runs.

Revision ID: 3c6f8a1d9b42
Revises: 91d6c3a8f4b2
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "3c6f8a1d9b42"
down_revision: Union[str, Sequence[str], None] = "91d6c3a8f4b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.create_table(
    "investigation_runs",
    sa.Column("id", sa.Uuid(), nullable=False),
    sa.Column("project_id", sa.Uuid(), nullable=False),
    sa.Column("incident_id", sa.Uuid(), nullable=False),
    sa.Column("requested_by_user_id", sa.Uuid(), nullable=True),
    sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    sa.Column("request_hash", sa.String(length=64), nullable=False),
    sa.Column("requested_integrations", sa.JSON(), nullable=False),
    sa.Column("request_criteria", sa.JSON(), nullable=False),
    sa.Column(
      "status",
      sa.String(length=16),
      server_default="running",
      nullable=False,
    ),
    sa.Column("aggregate_status", sa.String(length=16), nullable=True),
    sa.Column("integration_results", sa.JSON(), nullable=True),
    sa.Column(
      "evidence_ids",
      sa.JSON(),
      server_default="[]",
      nullable=False,
    ),
    sa.Column("failure_code", sa.String(length=64), nullable=True),
    sa.Column("failure_detail", sa.Text(), nullable=True),
    sa.Column(
      "attempt_count",
      sa.Integer(),
      server_default="1",
      nullable=False,
    ),
    sa.Column(
      "created_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.Column(
      "started_at",
      sa.DateTime(timezone=True),
      server_default=sa.func.now(),
      nullable=False,
    ),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint(
      "status IN ('running', 'succeeded', 'partial', 'failed', 'cancelled')",
      name="ck_investigation_runs_status",
    ),
    sa.CheckConstraint(
      "attempt_count >= 1",
      name="ck_investigation_runs_attempt_count",
    ),
    sa.ForeignKeyConstraint(
      ["incident_id"],
      ["incidents.id"],
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["project_id"],
      ["projects.id"],
      ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
      ["requested_by_user_id"],
      ["users.id"],
      ondelete="SET NULL",
    ),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint(
      "project_id",
      "incident_id",
      "requested_by_user_id",
      "idempotency_key",
      name="uq_investigation_runs_idempotency",
    ),
  )
  op.create_index(
    "ix_investigation_runs_incident_started",
    "investigation_runs",
    ["incident_id", "started_at"],
    unique=False,
  )


def downgrade() -> None:
  op.drop_index(
    "ix_investigation_runs_incident_started",
    table_name="investigation_runs",
  )
  op.drop_table("investigation_runs")
