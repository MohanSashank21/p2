"""Add bounded AI synthesis state to durable investigation runs.

Revision ID: 5e7a9c1d3f20
Revises: 3c6f8a1d9b42
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "5e7a9c1d3f20"
down_revision: Union[str, Sequence[str], None] = "3c6f8a1d9b42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "investigation_runs",
    sa.Column(
      "synthesis_status",
      sa.String(length=16),
      server_default="not_started",
      nullable=False,
    ),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_report", sa.JSON(), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_model", sa.String(length=128), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_prompt_version", sa.String(length=32), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_schema_version", sa.String(length=32), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_input_tokens", sa.Integer(), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_output_tokens", sa.Integer(), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_provider_attempts", sa.Integer(), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column(
      "synthesis_attempt_count",
      sa.Integer(),
      server_default="0",
      nullable=False,
    ),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_started_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_failure_code", sa.String(length=64), nullable=True),
  )
  op.add_column(
    "investigation_runs",
    sa.Column("synthesis_completed_at", sa.DateTime(timezone=True), nullable=True),
  )
  op.create_check_constraint(
    "ck_investigation_runs_synthesis_status",
    "investigation_runs",
    "synthesis_status IN ('not_started', 'running', 'succeeded', 'failed')",
  )
  op.create_check_constraint(
    "ck_investigation_runs_synthesis_attempt_count",
    "investigation_runs",
    "synthesis_attempt_count >= 0",
  )


def downgrade() -> None:
  op.drop_constraint(
    "ck_investigation_runs_synthesis_attempt_count",
    "investigation_runs",
    type_="check",
  )
  op.drop_constraint(
    "ck_investigation_runs_synthesis_status",
    "investigation_runs",
    type_="check",
  )
  op.drop_column("investigation_runs", "synthesis_completed_at")
  op.drop_column("investigation_runs", "synthesis_failure_code")
  op.drop_column("investigation_runs", "synthesis_started_at")
  op.drop_column("investigation_runs", "synthesis_attempt_count")
  op.drop_column("investigation_runs", "synthesis_provider_attempts")
  op.drop_column("investigation_runs", "synthesis_output_tokens")
  op.drop_column("investigation_runs", "synthesis_input_tokens")
  op.drop_column("investigation_runs", "synthesis_schema_version")
  op.drop_column("investigation_runs", "synthesis_prompt_version")
  op.drop_column("investigation_runs", "synthesis_model")
  op.drop_column("investigation_runs", "synthesis_report")
  op.drop_column("investigation_runs", "synthesis_status")
