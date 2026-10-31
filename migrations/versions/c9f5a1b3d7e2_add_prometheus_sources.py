"""Add Prometheus source endpoint configuration.

Revision ID: c9f5a1b3d7e2
Revises: 8d4a2c6e1f90
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c9f5a1b3d7e2"
down_revision: Union[str, Sequence[str], None] = "8d4a2c6e1f90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
  op.add_column(
    "incident_sources",
    sa.Column("prometheus_url", sa.Text(), nullable=True),
  )


def downgrade() -> None:
  op.drop_column("incident_sources", "prometheus_url")
