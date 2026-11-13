"""Add bounded investigation graph result to durable runs.

Revision ID: b7e9c2a6d401
Revises: a6f1c9d4e820
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b7e9c2a6d401"
down_revision: Union[str, Sequence[str], None] = "a6f1c9d4e820"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "investigation_runs",
    sa.Column("agent_report", sa.JSON(), nullable=True),
  )


def downgrade() -> None:
  op.drop_column("investigation_runs", "agent_report")
